import os, gc, sys, time, json, requests
import psutil, ctypes, win32con, win32gui
import win32file, win32api, subprocess
import xml.etree.ElementTree as et
from hashlib import md5, sha1, sha256
from pefile import PE, DIRECTORY_ENTRY
from PYAS_Language import translations
from PYAS_Function import function_list
from PYAS_Extension import slist, alist
from PYAS_Interface import Ui_MainWindow
from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from threading import Thread

class MainWindow_Controller(QtWidgets.QMainWindow):
    def __init__(self):
        super(MainWindow_Controller, self).__init__()
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.create_library()
        self.init_configs()
        self.init_whitelist()
        self.init_blocklist()
        self.init_tray_icon()
        self.setup_control()
        self.init_protect()
        self.show_pyas_ui()

    def init_tray_icon(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QFileIconProvider().icon(QFileInfo(self.pyas)))
        self.tray_icon.activated.connect(self.show_pyas_ui)
        self.tray_icon.show()

    def init_protect(self):
        self.protect_threading_init()
        self.protect_threading_init_2()
        self.protect_threading_init_3()
        self.protect_threading_init_4()
        self.protect_threading_init_5()
        self.block_window_threading_init()

    def init_configs(self):
        self.scan = False
        self.block_window = True
        self.pyas_opacity = 0
        self.pyas_version = "2.7.7"
        self.ui.Theme_White.setChecked(True)
        self.pyas = str(sys.argv[0]).replace("\\", "/")
        self.key = self.pyas_key()
        self.json = self.init_config_json()
        self.system_safe()
        self.init_config_lang()
        self.init_config_sens()
        self.init_config_ui()
        self.init_config_mbr()

    def create_library(self):
        try:
            if not os.path.exists("C:/Windows/SysWOW64/PYAS"):
                os.makedirs("C:/Windows/SysWOW64/PYAS")
        except Exception as e:
            self.pyas_bug_log(e)

    def writeConfig(self, config):
        try:
            with open("C:/Windows/SysWOW64/PYAS/PYAS.json", "w", encoding="utf-8") as f:
                f.write(json.dumps(config, indent=4, ensure_ascii=False))
        except Exception as e:
            self.pyas_bug_log(e)

    def init_whitelist(self):
        try:
            with open("C:/Windows/SysWOW64/PYAS/Whitelist.txt", "r", encoding="utf-8") as f:
                self.whitelist = [line.strip() for line in f.readlines()]
        except:
            self.whitelist = []

    def init_blocklist(self):
        try:
            with open("C:/Windows/SysWOW64/PYAS/Blocklist.txt", "r", encoding="utf-8") as f:
                self.blocklist = [line.strip() for line in f.readlines()]
        except:
            self.blocklist = []

    def init_config_mbr(self):
        try:
            with open(r"\\.\PhysicalDrive0", "r+b") as f:
                self.mbr_value = f.read(512)
        except:
            self.mbr_value = None

    def init_config_json(self):
        if not os.path.exists("C:/Windows/SysWOW64/PYAS/PYAS.json"):
            self.writeConfig({"language":"en_US","high_sensitivity":0,"cloud_services":1})
        with open("C:/Windows/SysWOW64/PYAS/PYAS.json", "r", encoding="utf-8") as f:
            return json.load(f)

    def init_config_lang(self):
        self.language = self.json.get("language", "en_US")
        if self.language == "zh_TW":
            self.ui.Language_Traditional_Chinese.setChecked(True)
        elif self.language == "zh_CN":
            self.ui.Language_Simplified_Chinese.setChecked(True)
        else:
            self.ui.Language_English.setChecked(True)
        self.lang_init_refresh()

    def init_config_sens(self):
        self.high_sensitivity = self.json.get("high_sensitivity", 0)
        if self.high_sensitivity == 1:
            self.ui.high_sensitivity_switch_Button.setText(self.text_Translate("已開啟"))
            self.ui.high_sensitivity_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")
        self.cloud_services = self.json.get("cloud_services", 1)
        if self.cloud_services == 1:
            self.ui.cloud_services_switch_Button.setText(self.text_Translate("已開啟"))
            self.ui.cloud_services_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")

    def setup_control(self):
        self.ui.Close_Button.clicked.connect(self.close)
        self.ui.Minimize_Button.clicked.connect(self.showMinimized)
        self.ui.Menu_Button.clicked.connect(self.ShowMenu)
        self.ui.State_Button.clicked.connect(self.Change_to_State_widget)
        self.ui.Protection_Button.clicked.connect(self.Change_to_Protection_widget)        
        self.ui.Virus_Scan_Button.clicked.connect(self.Change_to_Virus_Scan_widget)
        self.ui.Virus_Scan_Solve_Button.clicked.connect(self.virus_solve)
        self.ui.Virus_Scan_choose_Button.clicked.connect(self.virus_scan_choose_menu)
        self.ui.Virus_Scan_Break_Button.clicked.connect(self.virus_scan_break)
        self.ui.File_Scan_Button.clicked.connect(self.file_scan)
        self.ui.Path_Scan_Button.clicked.connect(self.path_scan)
        self.ui.Disk_Scan_Button.clicked.connect(self.disk_scan)
        self.ui.Tools_Button.clicked.connect(self.Change_to_Tools_widget)
        self.ui.System_Process_Manage_Button.clicked.connect(lambda:self.Change_Tools(self.ui.Process_widget))
        self.ui.Process_Tools_Back.clicked.connect(lambda:self.Back_To_More_Tools(self.ui.Process_widget))
        self.ui.About_Back.clicked.connect(self.ui.About_widget.hide)
        self.ui.Setting_Back.clicked.connect(self.Setting_Back)
        self.ui.Repair_System_Files_Button.clicked.connect(self.Repair_System_Files)
        self.ui.Clean_System_Files_Button.clicked.connect(self.Clean_System_Files)
        self.ui.Window_Block_Button.clicked.connect(self.Get_Software_Window)
        self.ui.Repair_System_Network_Button.clicked.connect(self.Repair_System_Network)
        self.ui.Process_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.Process_list.customContextMenuRequested.connect(self.Process_list_Menu)
        self.ui.Protection_switch_Button.clicked.connect(self.protect_threading_init)
        self.ui.Protection_switch_Button_2.clicked.connect(self.protect_threading_init_2)
        self.ui.Protection_switch_Button_3.clicked.connect(self.protect_threading_init_3)
        self.ui.Protection_switch_Button_4.clicked.connect(self.protect_threading_init_4)
        self.ui.Protection_switch_Button_5.clicked.connect(self.protect_threading_init_5)
        self.ui.high_sensitivity_switch_Button.clicked.connect(self.high_sensitivity_switch)
        self.ui.cloud_services_switch_Button.clicked.connect(self.cloud_services_switch)
        self.ui.Add_White_list_Button.clicked.connect(self.add_white_list)
        self.ui.Language_Traditional_Chinese.clicked.connect(self.Change_language)
        self.ui.Language_Simplified_Chinese.clicked.connect(self.Change_language)
        self.ui.Language_English.clicked.connect(self.Change_language)
        self.ui.Theme_White.clicked.connect(self.Change_Theme)
        self.ui.Theme_Black.clicked.connect(self.Change_Theme)
        self.ui.Theme_Green.clicked.connect(self.Change_Theme)
        self.ui.Theme_Yellow.clicked.connect(self.Change_Theme)
        self.ui.Theme_Blue.clicked.connect(self.Change_Theme)
        self.ui.Theme_Red.clicked.connect(self.Change_Theme)

    def init_config_ui(self):
        self.ui.widget_2.lower()
        self.ui.Navigation_Bar.raise_()
        self.ui.Window_widget.raise_()
        self.ui.Virus_Scan_choose_widget.raise_()
        self.Process_sim = QStringListModel()
        self.Process_quantity = []
        self.Process_list_all_pid = []
        self.Process_Timer = QTimer()
        self.Process_Timer.timeout.connect(self.Process_list)
        self.ui.License_terms.setText('''Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.''')
        self.effect_shadow = QtWidgets.QGraphicsDropShadowEffect(self)
        self.effect_shadow.setOffset(0,0)
        self.effect_shadow.setBlurRadius(10)
        self.effect_shadow.setColor(QtCore.Qt.gray)
        self.ui.widget_2.setGraphicsEffect(self.effect_shadow)
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
        self.ui.Virus_Scan_choose_widget.hide()
        self.ui.Virus_Scan_widget.hide()
        self.ui.Tools_widget.hide()
        self.ui.Protection_widget.hide()
        self.ui.Virus_Scan_Solve_Button.hide()
        self.ui.Virus_Scan_Break_Button.hide()
        self.ui.Process_widget.hide()
        self.ui.Setting_widget.hide()
        self.ui.About_widget.hide()

    def Change_language(self):
        try:
            self.ui.State_output.clear()
            if self.ui.Language_Traditional_Chinese.isChecked():
                self.json["language"] = "zh_TW"
                self.writeConfig(self.json)
            elif self.ui.Language_Simplified_Chinese.isChecked():
                self.json["language"] = "zh_CN"
                self.writeConfig(self.json)
            else:
                self.json["language"] = "en_US"
                self.writeConfig(self.json)
            self.lang_init_refresh()
        except Exception as e:
            self.pyas_bug_log(e)

    def text_Translate(self, text):
        for k, v in translations.get(self.json["language"], translations).items():
            text = text.replace(str(k), str(v))
        return text

    def lang_init_refresh(self):
        self.ui.State_title.setText(self.text_Translate("此裝置已受到防護" if self.safe else "此裝置當前不安全"))
        self.ui.Window_title.setText(self.text_Translate(f"PYAS V{self.pyas_version} {self.key}"))
        self.ui.PYAS_CopyRight.setText(self.text_Translate(f"Copyright© 2020-{max(int(time.strftime('%Y')), 2020)} PYAS Security"))
        self.ui.State_Button.setText(self.text_Translate(" 狀態"))
        self.ui.Virus_Scan_Button.setText(self.text_Translate(" 掃描"))
        self.ui.Tools_Button.setText(self.text_Translate(" 工具"))
        self.ui.Protection_Button.setText(self.text_Translate(" 防護"))
        self.ui.Virus_Scan_title.setText(self.text_Translate("病毒掃描"))
        self.ui.Virus_Scan_text.setText(self.text_Translate("請選擇掃描方式"))
        self.ui.Virus_Scan_choose_Button.setText(self.text_Translate("病毒掃描"))
        self.ui.File_Scan_Button.setText(self.text_Translate("檔案掃描"))
        self.ui.Path_Scan_Button.setText(self.text_Translate("路徑掃描"))
        self.ui.Disk_Scan_Button.setText(self.text_Translate("全盤掃描"))
        self.ui.Virus_Scan_Solve_Button.setText(self.text_Translate("立即刪除"))
        self.ui.Virus_Scan_Break_Button.setText(self.text_Translate("停止掃描"))
        self.ui.Process_Tools_Back.setText(self.text_Translate("返回"))
        self.ui.Process_Total_title.setText(self.text_Translate("進程總數:"))
        self.ui.Protection_title.setText(self.text_Translate("進程防護"))
        self.ui.Protection_illustrate.setText(self.text_Translate("啟用此選項可以攔截進程病毒"))
        self.ui.Protection_switch_Button.setText(self.text_Translate(self.ui.Protection_switch_Button.text()))
        self.ui.Protection_title_2.setText(self.text_Translate("檔案防護"))
        self.ui.Protection_illustrate_2.setText(self.text_Translate("啟用此選項可以監控檔案變更"))
        self.ui.Protection_switch_Button_2.setText(self.text_Translate(self.ui.Protection_switch_Button_2.text()))
        self.ui.Protection_title_3.setText(self.text_Translate("引導防護"))
        self.ui.Protection_illustrate_3.setText(self.text_Translate("啟用此選項可以修復引導分區"))
        self.ui.Protection_switch_Button_3.setText(self.text_Translate(self.ui.Protection_switch_Button_3.text()))
        self.ui.Protection_title_4.setText(self.text_Translate("註冊表防護"))
        self.ui.Protection_illustrate_4.setText(self.text_Translate("啟用此選項可以修復註冊表項目"))
        self.ui.Protection_switch_Button_4.setText(self.text_Translate(self.ui.Protection_switch_Button_4.text()))
        self.ui.Protection_title_5.setText(self.text_Translate("增強防護"))
        self.ui.Protection_illustrate_5.setText(self.text_Translate("啟用此選項可以增強系統防護"))
        self.ui.Protection_switch_Button_5.setText(self.text_Translate(self.ui.Protection_switch_Button_5.text()))
        self.ui.State_log.setText(self.text_Translate("日誌:"))
        self.ui.More_Tools_Back_Button.setText(self.text_Translate("工具>"))
        self.ui.System_Process_Manage_Button.setText(self.text_Translate("系統進程管理"))
        self.ui.Repair_System_Files_Button.setText(self.text_Translate("系統檔案修復"))
        self.ui.Clean_System_Files_Button.setText(self.text_Translate("系統垃圾清理"))
        self.ui.Window_Block_Button.setText(self.text_Translate("軟體彈窗攔截"))
        self.ui.Repair_System_Network_Button.setText(self.text_Translate("系統網路修復"))
        self.ui.About_Back.setText(self.text_Translate("返回"))
        self.ui.PYAS_Version.setText(self.text_Translate(f"PYAS V{self.pyas_version} {self.key}"))
        self.ui.GUI_Made_title.setText(self.text_Translate("介面製作:"))
        self.ui.GUI_Made_Name.setText(self.text_Translate("mtkiao"))
        self.ui.Core_Made_title.setText(self.text_Translate("核心製作:"))
        self.ui.Core_Made_Name.setText(self.text_Translate("87owo"))
        self.ui.Testers_title.setText(self.text_Translate("測試人員:"))
        self.ui.Testers_Name.setText(self.text_Translate("87owo"))
        self.ui.PYAS_URL_title.setText(self.text_Translate("官方網站:"))
        self.ui.PYAS_URL.setText(self.text_Translate("<html><head/><body><p><a href=\"https://github.com/87owo/PYAS\"><span style=\" text-decoration: underline; color:#000000;\">https://github.com/87owo/PYAS</span></a></p></body></html>"))
        self.ui.high_sensitivity_title.setText(self.text_Translate("高靈敏度模式"))
        self.ui.high_sensitivity_illustrate.setText(self.text_Translate("啟用此選項可以提高引擎的靈敏度"))
        self.ui.high_sensitivity_switch_Button.setText(self.text_Translate(self.ui.high_sensitivity_switch_Button.text()))
        self.ui.cloud_services_title.setText(self.text_Translate("雲端掃描服務"))
        self.ui.cloud_services_illustrate.setText(self.text_Translate("啟用此選項可以連接雲端掃描服務"))
        self.ui.cloud_services_switch_Button.setText(self.text_Translate(self.ui.cloud_services_switch_Button.text()))
        self.ui.Add_White_list_title.setText(self.text_Translate("增加到白名單"))
        self.ui.Add_White_list_illustrate.setText(self.text_Translate("此選項可以選擇檔案並增加到白名單"))
        self.ui.Add_White_list_Button.setText(self.text_Translate(self.ui.Add_White_list_Button.text()))
        self.ui.Add_White_list_Button.setText(self.text_Translate("選擇"))
        self.ui.Theme_title.setText(self.text_Translate("顯色主題"))
        self.ui.Theme_illustrate.setText(self.text_Translate("請選擇主題"))
        self.ui.Theme_White.setText(self.text_Translate("白色主題"))
        self.ui.Theme_Black.setText(self.text_Translate("黑色主題"))
        self.ui.Theme_Yellow.setText(self.text_Translate("黃色主題"))
        self.ui.Theme_Red.setText(self.text_Translate("紅色主題"))
        self.ui.Theme_Green.setText(self.text_Translate("綠色主題"))
        self.ui.Theme_Blue.setText(self.text_Translate("藍色主題"))
        self.ui.Setting_Back.setText(self.text_Translate("返回"))
        self.ui.Language_title.setText(self.text_Translate("顯示語言"))
        self.ui.Language_illustrate.setText(self.text_Translate("請選擇語言"))
        self.ui.License_terms_title.setText(self.text_Translate("許可條款:"))
    
    def Change_Theme(self):
        if self.ui.Theme_White.isChecked():
            self.ui.Window_widget.setStyleSheet("""QWidget#Window_widget {background-color:rgb(240,240,240);}""")
            self.ui.Navigation_Bar.setStyleSheet("""QWidget#Navigation_Bar {background-color:rgb(230,230,230);}""")
        elif self.ui.Theme_Red.isChecked():
            self.ui.Window_widget.setStyleSheet("""QWidget#Window_widget {background-color:rgb(255,150,150);}""")
            self.ui.Navigation_Bar.setStyleSheet("""QWidget#Navigation_Bar {background-color:rgb(255,140,140);}""")
        elif self.ui.Theme_Black.isChecked():
            self.ui.Window_widget.setStyleSheet("""QWidget#Window_widget {background-color:rgb(150,150,150);}""")
            self.ui.Navigation_Bar.setStyleSheet("""QWidget#Navigation_Bar {background-color:rgb(140,140,140);}""")
        elif self.ui.Theme_Green.isChecked():
            self.ui.Window_widget.setStyleSheet("""QWidget#Window_widget {background-color:rgb(150,255,150);}""")
            self.ui.Navigation_Bar.setStyleSheet("""QWidget#Navigation_Bar {background-color:rgb(130,255,130);}""")
        elif self.ui.Theme_Yellow.isChecked():
            self.ui.Window_widget.setStyleSheet("""QWidget#Window_widget {background-color:rgb(255,255,150);}""")
            self.ui.Navigation_Bar.setStyleSheet("""QWidget#Navigation_Bar {background-color:rgb(240,240,140);}""")
        elif self.ui.Theme_Blue.isChecked():
            self.ui.Window_widget.setStyleSheet("""QWidget#Window_widget {background-color:rgb(0,200,255);}""")
            self.ui.Navigation_Bar.setStyleSheet("""QWidget#Navigation_Bar {background-color:rgb(0,190,255);}""")

    def Change_animation(self,widget):
        x = 170
        y = widget.pos().y()
        self.anim = QPropertyAnimation(widget, b"geometry")
        widget.setGeometry(QtCore.QRect(x - 100,y, 671,481))
        self.anim.setKeyValueAt(0.2, QRect(x - 60,y,671,481))
        self.anim.setKeyValueAt(0.4, QRect(x - 10,y,671,481))
        self.anim.setKeyValueAt(0.7, QRect(x - 3,y,671,481))
        self.anim.setKeyValueAt(1, QRect(x,y,671,481))
        self.anim.start()

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

    def Change_animation5(self,widget,x,y,nx,ny):
        self.anim = QPropertyAnimation(widget, b"geometry")
        widget.setGeometry(QtCore.QRect(x,y - 45, nx,ny))
        self.anim.setKeyValueAt(0.2, QRect(x,y - 30,nx,ny))
        self.anim.setKeyValueAt(0.4, QRect(x,y - 10,nx,ny))
        self.anim.setKeyValueAt(0.7, QRect(x,y - 3,nx,ny))
        self.anim.setKeyValueAt(1, QRect(x,y,nx,ny))
        self.anim.start()

    def draw(self,widget,time):
        self.opacity.i = 0
        def timeout():
            if self.opacity.i < 100:
                self.opacity.i += 2
                self.opacity.setOpacity(self.opacity.i/100)
                widget.setGraphicsEffect(self.opacity)
            else:
                self.timer.stop()
        self.timer = QTimer()
        self.timer.timeout.connect(timeout)
        self.timer.start(5)

    def Change_to_State_widget(self):
        if self.ui.State_widget.isHidden():
            self.Change_animation_2(20,50)
            self.Change_animation_3(self.ui.State_widget,0.5)
            self.Change_animation(self.ui.State_widget)
            self.ui.State_widget.show()
            self.ui.Virus_Scan_widget.hide()
            self.ui.Tools_widget.hide()
            self.ui.Protection_widget.hide()
            self.ui.Process_widget.hide()
            self.ui.About_widget.hide()
            self.ui.Setting_widget.hide()

    def Change_to_Virus_Scan_widget(self):
        if self.ui.Virus_Scan_widget.isHidden():
            self.Change_animation_2(20,168)
            self.Change_animation_3(self.ui.Virus_Scan_widget,0.5)
            self.Change_animation(self.ui.Virus_Scan_widget)
            self.ui.State_widget.hide()
            self.ui.Virus_Scan_widget.show()
            self.ui.Tools_widget.hide()
            self.ui.Protection_widget.hide()
            self.ui.Process_widget.hide()
            self.ui.About_widget.hide()
            self.ui.Setting_widget.hide()

    def Change_to_Tools_widget(self):
        if self.ui.Tools_widget.isHidden():
            self.Change_animation_2(20,285)
            self.Change_animation_3(self.ui.Tools_widget,0.5)
            self.Change_animation(self.ui.Tools_widget)
            self.ui.State_widget.hide()
            self.ui.Virus_Scan_widget.hide()
            self.ui.Tools_widget.show()
            self.ui.Protection_widget.hide()
            self.ui.Process_widget.hide()
            self.ui.About_widget.hide()
            self.ui.Setting_widget.hide()

    def Change_to_Protection_widget(self):
        if self.ui.Protection_widget.isHidden():
            self.Change_animation_2(20,405)
            self.Change_animation_3(self.ui.Protection_widget,0.5)
            self.Change_animation(self.ui.Protection_widget)
            self.ui.State_widget.hide()
            self.ui.Virus_Scan_widget.hide()
            self.ui.Tools_widget.hide()
            self.ui.Protection_widget.show()
            self.ui.Process_widget.hide()
            self.ui.About_widget.hide()
            self.ui.Setting_widget.hide()

    def Change_Tools(self,widget):
        self.ui.Tools_widget.hide()
        self.ui.Setting_widget.hide()
        self.ui.About_widget.hide()
        if widget == self.ui.Process_widget:
            self.Process_Timer.start(0)
        elif widget == self.ui.System_Info_widget:
            self.System_Info_update()
        self.Change_animation_3(widget,0.5)
        self.Change_animation(widget)
        widget.show()

    def Back_To_More_Tools(self,widget):
        widget.hide()
        if widget == self.ui.Process_widget:
            self.Process_Timer.stop()
        self.Change_animation_3(self.ui.Tools_widget,0.5)
        self.Change_animation(self.ui.Tools_widget)
        self.ui.Tools_widget.show()

    def mousePressEvent(self, event):
        def updateOpacity():
            if self.pyas_opacity > 80 and self.m_flag == True:
                self.pyas_opacity -= 1
                self.setWindowOpacity(self.pyas_opacity/100)
            else:
                self.timer.stop()
        x = event.x()
        y = event.y()
        if event.button()==Qt.LeftButton and x >= 10 and x <= 841 and y >= 10 and y <= 49:
            self.m_flag=True
            self.m_Position=event.globalPos()-self.pos()
            event.accept()
            self.timer = QTimer()
            self.timer.timeout.connect(updateOpacity)
            self.timer.start(5)

    def mouseMoveEvent(self, QMouseEvent):
        try:
            if Qt.LeftButton and self.m_flag:
                self.move(QMouseEvent.globalPos()-self.m_Position)
                QApplication.processEvents()
                QMouseEvent.accept()
        except:
            pass

    def mouseReleaseEvent(self, QMouseEvent):
        def updateOpacity():
            if self.pyas_opacity < 100 and self.m_flag == False:
                self.pyas_opacity += 1
                self.setWindowOpacity(self.pyas_opacity/100)
            else:
                self.timer.stop()
        self.m_flag=False
        self.setCursor(QCursor(Qt.ArrowCursor))
        self.timer = QTimer()
        self.timer.timeout.connect(updateOpacity)
        self.timer.start(5)

    def paintEvent(self, event):
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

    def show_pyas_ui(self):
        self.show()
        while self.pyas_opacity < 100:
            time.sleep(0.001)
            self.pyas_opacity += 1
            self.setWindowOpacity(self.pyas_opacity/100)
            QApplication.processEvents()

    def hide_pyas_ui(self):
        while self.pyas_opacity > 0:
            time.sleep(0.001)
            self.pyas_opacity -= 1
            self.setWindowOpacity(self.pyas_opacity/100)
            QApplication.processEvents()
        self.hide()

    def showMinimized(self):
        self.hide_pyas_ui()
        self.system_notification(self.text_Translate("PYAS 已最小化到系統托盤圖標"))

    def closeEvent(self, event):
        if QMessageBox.warning(self,self.text_Translate("警告"),self.text_Translate("您確定要退出 PYAS 和所有防護嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
            self.block_window = False
            self.proc_protect = False
            self.file_protect = False
            self.mbr_protect = False
            self.reg_protect = False
            self.enh_protect = False
            self.tray_icon.hide()
            self.hide_pyas_ui()
            QApplication.instance().quit()
        event.ignore()

    def pyas_bug_log(self, e):
        try:
            print(f"[Error] {e}")
            QMessageBox.critical(self,self.text_Translate("錯誤"),self.text_Translate(f"錯誤: {e}"),QMessageBox.Ok)
        except:
            pass

    def system_notification(self,text):
        try:
            now_time = time.strftime('%Y/%m/%d %H:%M:%S')
            self.ui.State_output.append(f"[{now_time}] {text}")
            self.tray_icon.showMessage(now_time, text, 5)
        except:
            pass

    def pyas_key(self):
        try:
            with open(self.pyas, "rb") as f:
                file_md5 = str(md5(f.read()).hexdigest())
            for url in ["http://27.147.30.238:5001/pyas","https://api.pyas.cf/pyas"]:
                try:
                    response = requests.get(url, params={"key": file_md5}, timeout=3)
                    if response.status_code == 200 and response.text == "True":
                        return ""
                    else:
                        return "(安全密鑰錯誤)"
                except:
                    pass
            return "(網路連接錯誤)"
        except:
            return "(網路連接錯誤)"

    def ShowMenu(self):
        self.WindowMenu = QMenu()
        Main_Settings = QAction(self.text_Translate("設定"),self)
        Main_About = QAction(self.text_Translate("關於"),self)
        self.WindowMenu.addAction(Main_Settings)
        self.WindowMenu.addAction(Main_About)
        Qusetion = self.WindowMenu.exec_(self.ui.Menu_Button.mapToGlobal(QtCore.QPoint(0, 30)))
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

    def high_sensitivity_switch(self):
        sw_state = self.ui.high_sensitivity_switch_Button.text()
        if sw_state == self.text_Translate("已關閉"):
            self.high_sensitivity = 1
            self.json["high_sensitivity"] = 1
            self.writeConfig(self.json)
            self.ui.high_sensitivity_switch_Button.setText(self.text_Translate("已開啟"))
            self.ui.high_sensitivity_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")
        elif sw_state == self.text_Translate("已開啟"):
            self.high_sensitivity = 0
            self.json["high_sensitivity"] = 0
            self.writeConfig(self.json)
            self.ui.high_sensitivity_switch_Button.setText(self.text_Translate("已關閉"))
            self.ui.high_sensitivity_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,20,20,30);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,20,20,50);}""")

    def cloud_services_switch(self):
        sw_state = self.ui.cloud_services_switch_Button.text()
        if sw_state == self.text_Translate("已關閉"):
            self.cloud_services = 1
            self.json["cloud_services"] = 1
            self.writeConfig(self.json)
            self.ui.cloud_services_switch_Button.setText(self.text_Translate("已開啟"))
            self.ui.cloud_services_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")
        elif sw_state == self.text_Translate("已開啟"):
            self.cloud_services = 0
            self.json["cloud_services"] = 0
            self.writeConfig(self.json)
            self.ui.cloud_services_switch_Button.setText(self.text_Translate("已關閉"))
            self.ui.cloud_services_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,20,20,30);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,20,20,50);}""")

    def system_safe(self):
        try:
            self.safe = True
            self.ui.State_icon.setPixmap(QtGui.QPixmap(":/icon/Check.png"))
            self.ui.State_title.setText(self.text_Translate("此裝置已受到防護"))
        except:
            pass

    def system_unsafe(self):
        try:
            self.safe = False
            self.ui.State_icon.setPixmap(QtGui.QPixmap(":/icon/Close.png"))
            self.ui.State_title.setText(self.text_Translate("此裝置當前不安全"))
        except:
            pass

    def init_scan(self):
        self.scan = True
        self.Virus_List = []
        self.ui.Virus_Scan_Solve_Button.hide()
        self.ui.Virus_Scan_choose_widget.hide()
        self.ui.Virus_Scan_choose_Button.hide()
        self.Virus_List_output=QStringListModel()
        self.Virus_List_output.setStringList(self.Virus_List)
        self.ui.Virus_Scan_output.setModel(self.Virus_List_output)

    def virus_scan_break(self):
        self.scan = False
        self.ui.Virus_Scan_Break_Button.hide()
        self.ui.Virus_Scan_choose_Button.show()

    def virus_scan_choose_menu(self):
        if self.ui.Virus_Scan_choose_widget.isHidden():
            self.ui.Virus_Scan_choose_widget.show()
            self.Change_animation_4(self.ui.Virus_Scan_choose_widget,100,0,101)
        else:
            self.ui.Virus_Scan_choose_widget.hide()

    def write_scan(self,file):
        try:
            self.Virus_List.append(file)
            self.Virus_List_output.setStringList(self.Virus_List)
            self.ui.Virus_Scan_output.setModel(self.Virus_List_output)
        except:
            pass

    def answer_scan(self):
        if self.Virus_List != []:
            self.Virus_List_output.setStringList(self.Virus_List)
            self.ui.Virus_Scan_output.setModel(self.Virus_List_output)
            self.ui.Virus_Scan_Solve_Button.show()
            self.virus_scan_break()
            self.system_unsafe()
            text = self.text_Translate(f"當前發現 {len(self.Virus_List)} 個病毒")
        else:
            self.virus_scan_break()
            self.system_safe()
            text = self.text_Translate("當前未發現病毒")
        self.ui.Virus_Scan_text.setText(text)
        self.system_notification(text)

    def virus_solve(self):
        try:
            for line in self.Virus_List:
                try:
                    self.ui.Virus_Scan_text.setText(self.text_Translate("正在刪除: ")+line)
                    QApplication.processEvents()
                    os.remove(str(line))
                except:
                    continue
            self.Virus_List = []
            self.Virus_List_output.setStringList(self.Virus_List)
            self.ui.Virus_Scan_output.setModel(self.Virus_List_output)
            self.ui.Virus_Scan_text.setText(self.text_Translate("成功: 刪除成功"))
            self.ui.Virus_Scan_Solve_Button.hide()
            self.system_safe()
        except Exception as e:
            self.pyas_bug_log(e)

    def file_scan(self):
        try:
            file, filetype= QFileDialog.getOpenFileName(self,self.text_Translate("病毒掃描"),"C:/","")
            if file != "":
                self.init_scan()
                self.ui.Virus_Scan_text.setText(self.text_Translate("正在初始化中"))
                QApplication.processEvents()
                if file not in self.whitelist and ":/Windows" not in file:
                    if self.high_sensitivity == 0 and self.sign_scan(file):
                        if self.api_scan(file) or self.pe_scan(file):
                            self.write_scan(file)
                    elif self.high_sensitivity == 1:
                        if self.api_scan(file) or self.pe_scan(file):
                            self.write_scan(file)
                self.answer_scan()
                gc.collect()
        except Exception as e:
            self.pyas_bug_log(e)
            self.virus_scan_break()
            self.ui.Virus_Scan_text.setText(self.text_Translate("請選擇掃描方式"))

    def path_scan(self):
        try:
            path = QFileDialog.getExistingDirectory(self,self.text_Translate("病毒掃描"),"C:/")
            if path != "":
                self.init_scan()
                self.ui.Virus_Scan_text.setText(self.text_Translate("正在初始化中"))
                self.ui.Virus_Scan_Break_Button.show()
                QApplication.processEvents()
                self.traverse_path(path)
                self.answer_scan()
                gc.collect()
        except Exception as e:
            self.pyas_bug_log(e)
            self.virus_scan_break()
            self.ui.Virus_Scan_text.setText(self.text_Translate("請選擇掃描方式"))

    def disk_scan(self):
        try:
            self.init_scan()
            self.ui.Virus_Scan_text.setText(self.text_Translate("正在初始化中"))
            self.ui.Virus_Scan_Break_Button.show()
            QApplication.processEvents()
            for d in range(26):
                if os.path.exists(f"{chr(65+d)}:/"):
                    self.traverse_path(f"{chr(65+d)}:/")
            self.answer_scan()
            gc.collect()
        except Exception as e:
            self.pyas_bug_log(e)
            self.virus_scan_break()
            self.ui.Virus_Scan_text.setText(self.text_Translate("請選擇掃描方式"))

    def traverse_path(self,path):
        for fd in os.listdir(path):
            try:
                file = str(os.path.join(path,fd)).replace("\\", "/")
                if self.scan == False:
                    break
                elif file in self.whitelist or ":/$Recycle.Bin" in file or ":/Windows" in file:
                    continue
                elif os.path.isdir(file):
                    self.traverse_path(file)
                else:
                    self.ui.Virus_Scan_text.setText(self.text_Translate(f"正在掃描: ")+file)
                    QApplication.processEvents()
                    if self.high_sensitivity == 0 and self.sign_scan(file):
                        if str(os.path.splitext(fd)[1]).lower() in slist:
                            if self.api_scan(file) or self.pe_scan(file):
                                self.write_scan(file)
                    elif self.high_sensitivity == 1:
                        if self.api_scan(file) or self.pe_scan(file):
                            self.write_scan(file)
                gc.collect()
            except:
                continue

    def api_scan(self, file):
        try:
            if self.cloud_services == 1:
                with open(file, "rb") as f:
                    text = str(md5(f.read()).hexdigest())
                strBody = f'-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="md5s"\r\n\r\n{text}\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="format"\r\n\r\nXML\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="product"\r\n\r\n360zip\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="combo"\r\n\r\n360zip_main\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="v"\r\n\r\n2\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="osver"\r\n\r\n5.1\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="vk"\r\n\r\na03bc211\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="mid"\r\n\r\n8a40d9eff408a78fe9ec10a0e7e60f62\r\n-------------------------------7d83e2d7a141e--'
                response = requests.post('http://qup.f.360.cn/file_health_info.php', data=strBody, timeout=3)
                return response.status_code == 200 and float(et.fromstring(response.text).find('.//e_level').text) > 50
        except:
            return False

    def sign_scan(self, file):
        try:
            pe = PE(file, fast_load=True)
            pe.close()
            return pe.OPTIONAL_HEADER.DATA_DIRECTORY[DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].VirtualAddress == 0
        except:
            return True

    def pe_scan(self,file):
        try:
            fn = []
            pe = PE(file)
            pe.close()
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for func in entry.imports:
                    fn.append(str(func.name, "utf-8"))
            for vfl in function_list:
                QApplication.processEvents()
                if sum(1 for i in range(min(len(vfl), len(fn))) if vfl[i] == fn[i]) / min(len(vfl), len(fn)) > 0.5:
                    return True
            return False
        except:
            return False

    def Repair_System_Files(self):
        try:
            if QMessageBox.warning(self,self.text_Translate("警告"),self.text_Translate("您確定要修復系統檔案嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
                self.repair_system_wallpaper()
                self.repair_system_explorer()
                self.repair_system_restrictions()
                self.repair_system_file_type()
                self.repair_system_image()
                self.repair_system_icon()
                QMessageBox.information(self,self.text_Translate("成功"),self.text_Translate("修復系統檔案成功"),QMessageBox.Ok)
        except Exception as e:
            self.pyas_bug_log(e)

    def repair_system_icon(self):
        try:
            key = win32api.RegOpenKey(win32con.HKEY_CLASSES_ROOT, 'exefile', 0, win32con.KEY_ALL_ACCESS)
            win32api.RegSetValue(key, 'DefaultIcon', win32con.REG_SZ, '%1')
        except:
            pass
        try:
            key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, 'SOFTWARE\Classes\exefile', 0, win32con.KEY_ALL_ACCESS)
            win32api.RegSetValue(key, 'DefaultIcon', win32con.REG_SZ, '%1')
        except:
            pass

    def repair_system_image(self):
        try:
            key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',0,win32con.KEY_ALL_ACCESS | win32con.WRITE_OWNER)
            count = win32api.RegQueryInfoKey(key)[0]
            while count >= 0:
                try:
                    subKeyName = win32api.RegEnumKey(key, count)
                    win32api.RegDeleteKey(key, subKeyName)
                except:
                    pass
                count = count - 1
        except:
            pass

    def repair_system_file_type(self):
        try:
            data = [('.exe', 'exefile'),('exefile', 'Application')]
            key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, 'SOFTWARE\Classes', 0, win32con.KEY_ALL_ACCESS)
            for ext, value in data:
                win32api.RegSetValue(key, ext, win32con.REG_SZ, value)
            win32api.RegCloseKey(key)
            key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, 'SOFTWARE\Classes', 0, win32con.KEY_ALL_ACCESS)
            for ext, value in data:
                try:
                    win32api.RegSetValue(key, ext, win32con.REG_SZ, value)
                    keyopen = win32api.RegOpenKey(key, ext + r'\shell\open', 0, win32con.KEY_ALL_ACCESS)
                    win32api.RegSetValue(keyopen, 'command', win32con.REG_SZ, '"%1" %*')
                    win32api.RegCloseKey(keyopen)
                except:
                    pass
            win32api.RegCloseKey(key)
            key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts', 0, win32con.KEY_ALL_ACCESS)
            win32api.RegSetValue(key, '.exe', win32con.REG_SZ, '')
            win32api.RegCloseKey(key)
            key = win32api.RegOpenKey(win32con.HKEY_CLASSES_ROOT, None, 0, win32con.KEY_ALL_ACCESS)
            for ext, value in data:
                try:
                    win32api.RegSetValue(key, ext, win32con.REG_SZ, value)
                    keyopen = win32api.RegOpenKey(key, ext + r'\shell\open', 0, win32con.KEY_ALL_ACCESS)
                    win32api.RegSetValue(keyopen, 'command', win32con.REG_SZ, '"%1" %*')
                    win32api.RegCloseKey(keyopen)
                except:
                    pass
            win32api.RegCloseKey(key)
        except:
            pass

    def repair_system_restrictions(self):
        try:
            Permission = ["NoControlPanel", "NoDrives", "NoFileMenu", "NoFind", "NoRealMode", "NoRecentDocsMenu","NoSetFolders",
            "NoSetFolderOptions", "NoViewOnDrive", "NoClose", "NoRun", "NoDesktop", "NoLogOff", "NoFolderOptions", "RestrictRun","DisableCMD",
            "NoViewContexMenu", "HideClock", "NoStartMenuMorePrograms", "NoStartMenuMyGames", "NoStartMenuMyMusic" "NoStartMenuNetworkPlaces",
            "NoStartMenuPinnedList", "NoActiveDesktop", "NoSetActiveDesktop", "NoActiveDesktopChanges", "NoChangeStartMenu", "ClearRecentDocsOnExit",
            "NoFavoritesMenu", "NoRecentDocsHistory", "NoSetTaskbar", "NoSMHelp", "NoTrayContextMenu", "NoViewContextMenu", "NoWindowsUpdate",
            "NoWinKeys", "StartMenuLogOff", "NoSimpleNetlDList", "NoLowDiskSpaceChecks", "DisableLockWorkstation", "NoManageMyComputerVerb",
            "DisableTaskMgr", "DisableRegistryTools", "DisableChangePassword", "Wallpaper", "NoComponents", "NoAddingComponents", "Restrict_Run"]
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",0,win32con.KEY_ALL_ACCESS),"Explorer")
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",0,win32con.KEY_ALL_ACCESS),"Explorer")
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",0,win32con.KEY_ALL_ACCESS),"System")
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",0,win32con.KEY_ALL_ACCESS),"System")
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",0,win32con.KEY_ALL_ACCESS),"ActiveDesktop")
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,"SOFTWARE\Policies\Microsoft\Windows",0,win32con.KEY_ALL_ACCESS),"System")
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,"SOFTWARE\Policies\Microsoft\Windows",0,win32con.KEY_ALL_ACCESS),"System")
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,"Software\Policies\Microsoft",0,win32con.KEY_ALL_ACCESS),"MMC")
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,"Software\Policies\Microsoft\MMC",0,win32con.KEY_ALL_ACCESS),"{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}")
            keys = [win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",0,win32con.KEY_ALL_ACCESS),
            win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",0,win32con.KEY_ALL_ACCESS),
            win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",0,win32con.KEY_ALL_ACCESS),
            win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",0,win32con.KEY_ALL_ACCESS),
            win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop",0,win32con.KEY_ALL_ACCESS),
            win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,"SOFTWARE\Policies\Microsoft\Windows\System",0,win32con.KEY_ALL_ACCESS),
            win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,"SOFTWARE\Policies\Microsoft\Windows\System",0,win32con.KEY_ALL_ACCESS),
            win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,"Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}",0,win32con.KEY_ALL_ACCESS)]
            for key in keys:
                for i in Permission:
                    try:
                        win32api.RegDeleteValue(key,i)
                    except:
                        pass
                win32api.RegCloseKey(key)
        except:
            pass

    def repair_system_wallpaper(self):
        try:
            ctypes.windll.user32.SystemParametersInfoW(0x0014, 0, 'C:/Windows/web/wallpaper/windows/img0.jpg', 0x01 | 0x02)
        except:
            pass

    def repair_system_explorer(self):
        try:
            if not self.is_process_running("explorer.exe"):
                subprocess.run("explorer.exe", check=True)
        except:
            pass

    def is_process_running(self, name):
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == name:
                return True
        return False

    def Clean_System_Files(self):
        try:
            if QMessageBox.warning(self,self.text_Translate("警告"),self.text_Translate("您確定要清理系統垃圾嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
                self.total_deleted_size = 0
                self.traverse_temp_files(f"C:/Users/{os.getlogin()}/AppData/Local/Temp")
                self.traverse_temp_files(f"C:/Windows/Temp")
                self.traverse_temp_files(f"C:/$Recycle.Bin")
                QMessageBox.information(self,self.text_Translate("成功"),self.text_Translate(f"成功清理了 {self.total_deleted_size} 位元的系統垃圾"),QMessageBox.Ok)
        except Exception as e:
            self.pyas_bug_log(e)

    def traverse_temp_files(self, path):
        for fd in os.listdir(path):
            try:
                file = str(os.path.join(path,fd)).replace("\\", "/")
                QApplication.processEvents()
                if os.path.isdir(file):
                    self.traverse_temp_files(file)
                else:
                    file_size = os.path.getsize(file)
                    os.remove(file)
                    self.total_deleted_size += file_size
            except:
                continue

    def add_white_list(self):
        try:
            file, filetype= QFileDialog.getOpenFileName(self,self.text_Translate("增加到白名單"),"C:/","All File *.*")
            if file not in ["", "PYAS"]:
                if str(file.replace("\\", "/")) not in self.whitelist:
                    if QMessageBox.warning(self,self.text_Translate("警告"),self.text_Translate("您確定要增加到白名單嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
                        try:
                            self.whitelist.append(str(file.replace("\\", "/")))
                            with open("C:/Windows/SysWOW64/PYAS/Whitelist.txt", "a+", encoding="utf-8") as f:
                                f.write(str(file.replace("\\", "/"))+'\n')
                            QMessageBox.information(self,self.text_Translate("成功"),self.text_Translate(f"成功增加到白名單: ")+str(file.replace("\\", "/")),QMessageBox.Ok)
                        except:
                            self.pyas_bug_log('增加到白名單失敗')
                elif QMessageBox.warning(self,self.text_Translate("警告"),self.text_Translate(f"您確定要取消增加到白名單嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
                    try:
                        self.whitelist.remove(str(file.replace("\\", "/")))
                        with open("C:/Windows/SysWOW64/PYAS/Whitelist.txt", "w", encoding="utf-8") as f:
                            for file in self.whitelist:
                                f.write(f'{file}\n')
                        QMessageBox.information(self,self.text_Translate("成功"),self.text_Translate(f"成功取消增加到白名單: ")+str(file.replace("\\", "/")),QMessageBox.Ok)
                    except:
                        self.pyas_bug_log('取消增加到白名單失敗')
        except Exception as e:
            self.pyas_bug_log(e)

    def Get_Software_Window(self):
        try:
            self.block_window = False
            if QMessageBox.warning(self,self.text_Translate("警告"),self.text_Translate("請選擇要攔截的軟體彈窗"),QMessageBox.Yes|QMessageBox.No) == 16384:
                while self.block_window == False:
                    window_name = str(win32gui.GetWindowText(win32gui.GetForegroundWindow()))
                    QApplication.processEvents()
                    if window_name not in ["", "PYAS"]:
                        if window_name not in self.blocklist:
                            if QMessageBox.warning(self,self.text_Translate("警告"),self.text_Translate(f"您確定要攔截 {window_name} 嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
                                try:
                                    self.blocklist.append(window_name)
                                    with open("C:/Windows/SysWOW64/PYAS/Blocklist.txt", "a+", encoding="utf-8") as f:
                                        f.write(f'{window_name}\n')
                                    QMessageBox.information(self,self.text_Translate("成功"),self.text_Translate(f"成功增加到彈窗攔截: ")+window_name,QMessageBox.Ok)
                                except:
                                    self.pyas_bug_log('增加到彈窗攔截失敗')
                        elif QMessageBox.warning(self,self.text_Translate("警告"),self.text_Translate(f"您確定要取消攔截 {window_name} 嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
                            try:
                                self.blocklist.remove(window_name)
                                with open("C:/Windows/SysWOW64/PYAS/Blocklist.txt", "w", encoding="utf-8") as f:
                                    for window_name in self.blocklist:
                                        f.write(f'{window_name}\n')
                                QMessageBox.information(self,self.text_Translate("成功"),self.text_Translate(f"成功取消彈窗攔截: ")+window_name,QMessageBox.Ok)
                            except:
                                self.pyas_bug_log('取消到彈窗攔截失敗')
                        self.block_window = True
            self.block_window_threading_init()
        except Exception as e:
            self.pyas_bug_log(e) 

    def block_window_threading_init(self):
        self.block_window = True
        Thread(target=self.block_software_window).start()

    def block_software_window(self):
        while self.block_window:
            time.sleep(0.2)
            for window_name in self.blocklist:
                try:
                    win32gui.PostMessage(win32gui.FindWindow(None, window_name), win32con.WM_SYSCOMMAND, win32con.SC_CLOSE, 0)
                except:
                    pass

    def Repair_System_Network(self):
        try:
            if QMessageBox.warning(self,self.text_Translate("警告"),self.text_Translate("您確定要修復系統網路嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
                subprocess.run("netsh winsock reset", check=True)
                if QMessageBox.warning(self,self.text_Translate("警告"),self.text_Translate("使用此選項需要重啟，您確定要重啟嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
                    subprocess.run("shutdown -r -t 0", check=True)
        except Exception as e:
            self.pyas_bug_log(e)

    def Setting_Back(self):
        self.ui.Navigation_Bar.show()
        self.ui.Setting_widget.hide()

    def Process_list(self):
        try:
            self.Process_list_app = []
            self.Process_list_app_pid = []
            self.Process_list_iter = psutil.process_iter()
            for p in self.Process_list_iter:
                try:
                    self.Process_list_app.append(f"{p.name()} ({p.pid}) > {p.exe()}")
                    self.Process_list_app_pid.append(p.pid)
                    QApplication.processEvents()
                except:
                    pass
            self.Process_list_all_pid = self.Process_list_app_pid
            if len(self.Process_list_app_pid) != self.Process_quantity:
                self.Process_quantity = len(self.Process_list_app_pid)
                self.ui.Process_Total_View.setText(str(self.Process_quantity))
                self.Process_sim.setStringList(self.Process_list_app)
                self.ui.Process_list.setModel(self.Process_sim)
        except Exception as e:
            self.pyas_bug_log(e)

    def Process_list_Menu(self,pos):
        try:
            for i in self.ui.Process_list.selectedIndexes():
                self.pid = self.Process_list_all_pid[i.row()]
            self.Process_popMenu = QMenu()
            self.kill_Process = QAction(self.text_Translate("結束進程"),self)
            self.Process_popMenu.addAction(self.kill_Process)
            if self.Process_popMenu.exec_(self.ui.Process_list.mapToGlobal(pos)) == self.kill_Process:
                for p in psutil.process_iter():
                    if p.pid == self.pid:
                        p.kill()
        except:
            pass

    def protect_threading_init(self):
        if self.ui.Protection_switch_Button.text() == self.text_Translate("已開啟"):
            self.proc_protect = False
            self.ui.Protection_switch_Button.setText(self.text_Translate("已關閉"))
            self.ui.Protection_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,20,20,30);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,20,20,50);}""")
        else:
            self.proc_protect = True
            self.ui.Protection_switch_Button.setText(self.text_Translate("已開啟"))
            self.ui.Protection_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")
            Thread(target=self.protect_system_processes).start()

    def protect_threading_init_2(self):
        if self.ui.Protection_switch_Button_2.text() == self.text_Translate("已開啟"):
            self.file_protect = False
            self.ui.Protection_switch_Button_2.setText(self.text_Translate("已關閉"))
            self.ui.Protection_switch_Button_2.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,20,20,30);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,20,20,50);}""")
        else:
            self.file_protect = True
            self.ui.Protection_switch_Button_2.setText(self.text_Translate("已開啟"))
            self.ui.Protection_switch_Button_2.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")
            for d in range(26):
                if os.path.exists(f"{chr(65+d)}:/"):
                    Thread(target=self.protect_system_file, args=(f"{chr(65+d)}:/",)).start()

    def protect_threading_init_3(self):
        if self.ui.Protection_switch_Button_3.text() == self.text_Translate("已開啟"):
            self.mbr_protect = False
            self.ui.Protection_switch_Button_3.setText(self.text_Translate("已關閉"))
            self.ui.Protection_switch_Button_3.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,20,20,30);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,20,20,50);}""")
        else:
            self.mbr_protect = True
            self.ui.Protection_switch_Button_3.setText(self.text_Translate("已開啟"))
            self.ui.Protection_switch_Button_3.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")
            Thread(target=self.protect_system_mbr_repair).start()

    def protect_threading_init_4(self):
        if self.ui.Protection_switch_Button_4.text() == self.text_Translate("已開啟"):
            self.reg_protect = False
            self.ui.Protection_switch_Button_4.setText(self.text_Translate("已關閉"))
            self.ui.Protection_switch_Button_4.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,20,20,30);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,20,20,50);}""")
        else:
            self.reg_protect = True
            self.ui.Protection_switch_Button_4.setText(self.text_Translate("已開啟"))
            self.ui.Protection_switch_Button_4.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")
            Thread(target=self.protect_system_reg_repair).start()

    def protect_threading_init_5(self):
        if self.ui.Protection_switch_Button_5.text() == self.text_Translate("已開啟"):
            self.enh_protect = False
            self.ui.Protection_switch_Button_5.setText(self.text_Translate("已關閉"))
            self.ui.Protection_switch_Button_5.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,20,20,30);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,20,20,50);}""")
        else:
            self.enh_protect = True
            self.ui.Protection_switch_Button_5.setText(self.text_Translate("已開啟"))
            self.ui.Protection_switch_Button_5.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")
            Thread(target=self.protect_system_enhanced).start()

    def protect_system_processes(self):
        existing_proc = {}
        for proc in psutil.process_iter(['name', 'exe']):
            existing_proc[str(proc.info['name'])] = str(proc.info['exe']).replace("\\", "/")
        while self.proc_protect:
            try:
                time.sleep(0.2)
                current_proc = {}
                for proc in psutil.process_iter(['name', 'exe']):
                    current_proc[str(proc.info['name'])] = str(proc.info['exe']).replace("\\", "/")
                new_proc = {name: path for name, path in current_proc.items() if name not in existing_proc}
                if new_proc:
                    for self.p_name, self.p_file in new_proc.items():
                        if self.p_file == self.pyas or self.p_file in self.whitelist:
                            continue
                        elif ":/Windows" in self.p_file or ":/Program" in self.p_file:
                            continue
                        elif self.high_sensitivity == 1 and self.sign_scan(self.p_file):
                            for p in psutil.process_iter(['name', 'exe']):
                                if p.info['name'] == self.p_name:
                                    p.kill()
                            self.system_notification(self.text_Translate("無效簽名攔截: ")+self.p_name)
                        elif self.api_scan(self.p_file):
                            for p in psutil.process_iter(['name', 'exe']):
                                if p.info['name'] == self.p_name:
                                    p.kill()
                            self.system_notification(self.text_Translate("惡意軟體攔截: ")+self.p_name)
                        elif self.pe_scan(self.p_file):
                            for p in psutil.process_iter(['name', 'exe']):
                                if p.info['name'] == self.p_name:
                                    p.kill()
                            self.system_notification(self.text_Translate("可疑檔案攔截: ")+self.p_name)
                        else:
                            self.p_check = self.p_name
                        gc.collect()
                existing_proc = current_proc
            except:
                pass

    def protect_system_track(self,proc):
        try:
            if self.is_process_running(proc):
                for p in psutil.process_iter(['name', 'exe']):
                    if p.info['name'] == proc:
                        p.kill()
                        return True
            return False
        except:
            return False

    def protect_system_file(self,path):
        hDir = win32file.CreateFile(path,win32con.GENERIC_READ,win32con.FILE_SHARE_READ|win32con.FILE_SHARE_WRITE|win32con.FILE_SHARE_DELETE,None,win32con.OPEN_EXISTING,win32con.FILE_FLAG_BACKUP_SEMANTICS,None)
        while self.file_protect:
            try:
                for action, file in win32file.ReadDirectoryChangesW(hDir,1024,True,win32con.FILE_NOTIFY_CHANGE_FILE_NAME|win32con.FILE_NOTIFY_CHANGE_DIR_NAME|win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES|win32con.FILE_NOTIFY_CHANGE_SIZE|win32con.FILE_NOTIFY_CHANGE_LAST_WRITE|win32con.FILE_NOTIFY_CHANGE_SECURITY,None,None):
                    file = str(f"{path}{file}").replace("\\", "/")
                    file_type = str(os.path.splitext(file)[1]).lower()
                    if file == self.pyas or file in self.whitelist:
                        continue
                    elif ":/Windows" in file or ":/Program" in file:
                        continue
                    elif action == 4 and file_type in alist:
                        if self.protect_system_track(self.p_check):
                            self.system_notification(self.text_Translate("勒索軟體攔截: ")+self.p_check)
                    elif action == 3 and file_type in slist:
                        if self.sign_scan(file) and self.api_scan(file):
                            os.remove(file)
                            self.system_notification(self.text_Translate("惡意軟體刪除: ")+file)
                    gc.collect()
            except:
                pass

    def protect_system_mbr_repair(self):
        while self.mbr_protect and self.mbr_value != None:
            try:
                time.sleep(0.2)
                with open(r"\\.\PhysicalDrive0", "r+b") as f:
                    if f.read(512) != self.mbr_value:
                        f.seek(0)
                        f.write(self.mbr_value)
            except:
                pass

    def protect_system_reg_repair(self):
        while self.reg_protect:
            try:
                time.sleep(0.2)
                self.repair_system_restrictions()
            except:
                pass

    def protect_system_enhanced(self):
        while self.enh_protect:
            try:
                time.sleep(0.2)
                self.repair_system_file_type()
                self.repair_system_image()
                self.repair_system_icon()
            except:
                pass

if __name__ == '__main__':
    QtCore.QCoreApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    QtGui.QGuiApplication.setAttribute(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QtWidgets.QApplication(sys.argv)
    MainWindow_Controller()
    sys.exit(app.exec_())
