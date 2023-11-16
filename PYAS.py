import os, gc, sys, time, json, psutil
import hashlib, pefile, socket, msvcrt
import requests, pyperclip, win32file
import win32gui, win32api, win32con
import xml.etree.ElementTree as xmlet
from PYAS_Function import function_list
from PYAS_Extension import slist, alist
from PYAS_Language import translate_dict
from PYAS_Interface import Ui_MainWindow
from threading import Thread
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

class MainWindow_Controller(QMainWindow):
    def __init__(self):
        super(MainWindow_Controller, self).__init__()
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.pyas = str(sys.argv[0]).replace("\\", "/")
        self.pyas_version = "2.9.2"
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.init_tray_icon()
        self.init_virus_list()
        self.init_state_safe()
        self.init_config_path()
        self.init_config_read()
        self.init_config_json()
        self.init_config_list()
        self.init_config_boot()
        self.init_config_qtui()
        self.init_change_lang()
        self.init_control()
        self.show_pyas_ui()
        self.init_threads()

    def init_threads(self):
        self.protect_proc_init()
        self.protect_file_init()
        self.protect_boot_init()
        self.protect_reg_init()
        self.protect_net_init()
        self.block_window_init()

    def init_tray_icon(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QFileIconProvider().icon(QFileInfo(self.pyas)))
        self.tray_icon.activated.connect(self.show_pyas_ui)
        self.tray_icon.show()

    def init_config_path(self):
        try:
            if not os.path.exists("C:/ProgramData/PYAS"):
                os.makedirs("C:/ProgramData/PYAS")
        except Exception as e:
            self.bug_event(e)

    def write_config(self, config):
        try:
            with open("C:/ProgramData/PYAS/PYAS.json", "w", encoding="utf-8") as f:
                f.write(json.dumps(config, indent=4, ensure_ascii=False))
        except:
            pass

    def init_virus_list(self):
        try:
            self.virus_lock = {}
            self.virus_list = []
            self.virus_list_ui = []
        except:
            pass

    def init_config_list(self):
        try:
            self.whitelist = []
            if os.path.exists("C:/ProgramData/PYAS/Whitelist.ini"):
                with open("C:/ProgramData/PYAS/Whitelist.ini", "r", encoding="utf-8") as f:
                    self.whitelist = [line.strip() for line in f.readlines()]
            self.blocklist = []
            if os.path.exists("C:/ProgramData/PYAS/Blocklist.ini"):
                with open("C:/ProgramData/PYAS/Blocklist.ini", "r", encoding="utf-8") as f:
                    self.blocklist = [line.strip() for line in f.readlines()]
        except:
            pass

    def init_config_boot(self):
        try:
            with open(r"\\.\PhysicalDrive0", "r+b") as f:
                self.mbr_value = f.read(512)
            if self.mbr_value[510:512] != b'\x55\xAA':
                self.mbr_value = False
        except:
            self.mbr_value = False

    def init_config_read(self):
        try:
            if not os.path.exists("C:/ProgramData/PYAS/PYAS.json"):
                self.write_config({"language":"en_US","high_sensitivity":0,"cloud_services":1})
            with open("C:/ProgramData/PYAS/PYAS.json", "r", encoding="utf-8") as f:
                self.json = json.load(f)
        except:
            self.write_config({"language":"en_US","high_sensitivity":0,"cloud_services":1})
            with open("C:/ProgramData/PYAS/PYAS.json", "r", encoding="utf-8") as f:
                self.json = json.load(f)

    def init_config_json(self):
        self.high_sensitivity = self.json.get("high_sensitivity", 0)
        if self.high_sensitivity == 1:
            self.ui.high_sensitivity_switch_Button.setText(self.trans("已開啟"))
            self.ui.high_sensitivity_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")
        self.cloud_services = self.json.get("cloud_services", 1)
        if self.cloud_services == 1:
            self.ui.cloud_services_switch_Button.setText(self.trans("已開啟"))
            self.ui.cloud_services_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")
        self.language = self.json.get("language", "en_US")
        if self.language == "zh_TW":
            self.ui.Language_Traditional_Chinese.setChecked(True)
        elif self.language == "zh_CN":
            self.ui.Language_Simplified_Chinese.setChecked(True)
        else:
            self.ui.Language_English.setChecked(True)

    def init_control(self):
        self.ui.Theme_White.setChecked(True)
        self.ui.Close_Button.clicked.connect(self.close)
        self.ui.Minimize_Button.clicked.connect(self.showMinimized)
        self.ui.Menu_Button.clicked.connect(self.show_menu)
        self.ui.State_Button.clicked.connect(self.change_state_widget)
        self.ui.Tools_Button.clicked.connect(self.change_tools_widget)    
        self.ui.Virus_Scan_Button.clicked.connect(self.change_scan_widget)
        self.ui.Protection_Button.clicked.connect(self.change_protect_widget)
        self.ui.Virus_Scan_output.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.Virus_Scan_output.customContextMenuRequested.connect(self.Virus_Scan_output_menu)
        self.ui.System_Process_Manage_Button.clicked.connect(lambda:self.change_tools(self.ui.Process_widget))
        self.ui.Process_Tools_Back.clicked.connect(lambda:self.back_to_tools(self.ui.Process_widget))
        self.ui.Virus_Scan_Solve_Button.clicked.connect(self.virus_solve)
        self.ui.Virus_Scan_choose_Button.clicked.connect(self.virus_scan_menu)
        self.ui.Virus_Scan_Break_Button.clicked.connect(self.virus_scan_break)
        self.ui.File_Scan_Button.clicked.connect(self.file_scan)
        self.ui.Path_Scan_Button.clicked.connect(self.path_scan)
        self.ui.Disk_Scan_Button.clicked.connect(self.disk_scan)
        self.ui.About_Back.clicked.connect(self.ui.About_widget.hide)
        self.ui.Setting_Back.clicked.connect(self.setting_back)
        self.ui.Repair_System_Files_Button.clicked.connect(self.repair_system)
        self.ui.Clean_System_Files_Button.clicked.connect(self.clean_system)
        self.ui.Window_Block_Button.clicked.connect(self.get_software_window)
        self.ui.Repair_System_Network_Button.clicked.connect(self.repair_network)
        self.ui.Process_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.Process_list.customContextMenuRequested.connect(self.process_list_menu)
        self.ui.Protection_switch_Button.clicked.connect(self.protect_proc_init)
        self.ui.Protection_switch_Button_2.clicked.connect(self.protect_file_init)
        self.ui.Protection_switch_Button_3.clicked.connect(self.protect_boot_init)
        self.ui.Protection_switch_Button_4.clicked.connect(self.protect_reg_init)
        self.ui.Protection_switch_Button_5.clicked.connect(self.protect_net_init)
        self.ui.high_sensitivity_switch_Button.clicked.connect(self.change_sensitive)
        self.ui.cloud_services_switch_Button.clicked.connect(self.change_cloud_service)
        self.ui.Add_White_list_Button.clicked.connect(self.add_white_list)
        self.ui.Language_Traditional_Chinese.clicked.connect(self.init_change_lang)
        self.ui.Language_Simplified_Chinese.clicked.connect(self.init_change_lang)
        self.ui.Language_English.clicked.connect(self.init_change_lang)
        self.ui.Theme_White.clicked.connect(self.change_theme)
        self.ui.Theme_Black.clicked.connect(self.change_theme)
        self.ui.Theme_Green.clicked.connect(self.change_theme)
        self.ui.Theme_Yellow.clicked.connect(self.change_theme)
        self.ui.Theme_Blue.clicked.connect(self.change_theme)
        self.ui.Theme_Red.clicked.connect(self.change_theme)

    def init_config_qtui(self):
        self.ui.widget_2.lower()
        self.ui.Navigation_Bar.raise_()
        self.ui.Window_widget.raise_()
        self.ui.Virus_Scan_choose_widget.raise_()
        self.Process_sim = QStringListModel()
        self.Process_quantity = []
        self.Process_list_all_pid = []
        self.Process_Timer = QTimer()
        self.Process_Timer.timeout.connect(self.process_list)
        self.ui.License_terms.setText('''Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.''')
        self.effect_shadow = QGraphicsDropShadowEffect(self)
        self.effect_shadow.setOffset(0,0)
        self.effect_shadow.setBlurRadius(10)
        self.effect_shadow.setColor(Qt.gray)
        self.ui.widget_2.setGraphicsEffect(self.effect_shadow)
        self.effect_shadow2 = QGraphicsDropShadowEffect(self)
        self.effect_shadow2.setOffset(0,0)
        self.effect_shadow2.setBlurRadius(10)
        self.effect_shadow2.setColor(Qt.gray) 
        self.ui.Navigation_Bar.setGraphicsEffect(self.effect_shadow2)
        self.effect_shadow3 = QGraphicsDropShadowEffect(self)
        self.effect_shadow3.setOffset(0,0)
        self.effect_shadow3.setBlurRadius(7)
        self.effect_shadow3.setColor(Qt.gray) 
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
        self.ui.State_output.style().polish(self.ui.State_output.verticalScrollBar())
        self.ui.Virus_Scan_output.style().polish(self.ui.Virus_Scan_output.verticalScrollBar())

    def init_change_lang(self):
        try:
            self.ui.State_output.clear()
            if self.ui.Language_Traditional_Chinese.isChecked():
                self.json["language"] = "zh_TW"
            elif self.ui.Language_Simplified_Chinese.isChecked():
                self.json["language"] = "zh_CN"
            elif self.ui.Language_English.isChecked():
                self.json["language"] = "en_US"
            self.write_config(self.json)
            self.init_lang_text()
        except Exception as e:
            self.bug_event(e)

    def trans(self, text):
        for k, v in translate_dict.get(self.json["language"], translate_dict).items():
            text = text.replace(str(k), str(v))
        return text

    def init_lang_text(self):
        self.ui.State_title.setText(self.trans("此裝置已受到防護" if self.safe else "此裝置當前不安全"))
        self.ui.Window_title.setText(self.trans(f"PYAS V{self.pyas_version}"))
        self.ui.PYAS_CopyRight.setText(self.trans(f"Copyright© 2020-{max(int(time.strftime('%Y')), 2020)} PYAS Security"))
        self.ui.State_Button.setText(self.trans(" 狀態"))
        self.ui.Virus_Scan_Button.setText(self.trans(" 掃描"))
        self.ui.Tools_Button.setText(self.trans(" 工具"))
        self.ui.Protection_Button.setText(self.trans(" 防護"))
        self.ui.Virus_Scan_title.setText(self.trans("病毒掃描"))
        self.ui.Virus_Scan_text.setText(self.trans("請選擇掃描方式"))
        self.ui.Virus_Scan_choose_Button.setText(self.trans("病毒掃描"))
        self.ui.File_Scan_Button.setText(self.trans("檔案掃描"))
        self.ui.Path_Scan_Button.setText(self.trans("路徑掃描"))
        self.ui.Disk_Scan_Button.setText(self.trans("全盤掃描"))
        self.ui.Virus_Scan_Solve_Button.setText(self.trans("立即刪除"))
        self.ui.Virus_Scan_Break_Button.setText(self.trans("停止掃描"))
        self.ui.Process_Tools_Back.setText(self.trans("返回"))
        self.ui.Process_Total_title.setText(self.trans("進程總數:"))
        self.ui.Protection_title.setText(self.trans("進程防護"))
        self.ui.Protection_illustrate.setText(self.trans("啟用此選項可以攔截進程病毒"))
        self.ui.Protection_switch_Button.setText(self.trans(self.ui.Protection_switch_Button.text()))
        self.ui.Protection_title_2.setText(self.trans("檔案防護"))
        self.ui.Protection_illustrate_2.setText(self.trans("啟用此選項可以監控檔案變更"))
        self.ui.Protection_switch_Button_2.setText(self.trans(self.ui.Protection_switch_Button_2.text()))
        self.ui.Protection_title_3.setText(self.trans("引導防護"))
        self.ui.Protection_illustrate_3.setText(self.trans("啟用此選項可以修復引導分區"))
        self.ui.Protection_switch_Button_3.setText(self.trans(self.ui.Protection_switch_Button_3.text()))
        self.ui.Protection_title_4.setText(self.trans("註冊表防護"))
        self.ui.Protection_illustrate_4.setText(self.trans("啟用此選項可以修復註冊表項目"))
        self.ui.Protection_switch_Button_4.setText(self.trans(self.ui.Protection_switch_Button_4.text()))
        self.ui.Protection_title_5.setText(self.trans("網路防護"))
        self.ui.Protection_illustrate_5.setText(self.trans("啟用此選項可以監控網路通訊"))
        self.ui.Protection_switch_Button_5.setText(self.trans(self.ui.Protection_switch_Button_5.text()))
        self.ui.State_log.setText(self.trans("日誌:"))
        self.ui.More_Tools_Back_Button.setText(self.trans("工具>"))
        self.ui.System_Process_Manage_Button.setText(self.trans("系統進程管理"))
        self.ui.Repair_System_Files_Button.setText(self.trans("系統檔案修復"))
        self.ui.Clean_System_Files_Button.setText(self.trans("系統垃圾清理"))
        self.ui.Window_Block_Button.setText(self.trans("軟體彈窗攔截"))
        self.ui.Repair_System_Network_Button.setText(self.trans("系統網路修復"))
        self.ui.About_Back.setText(self.trans("返回"))
        self.ui.PYAS_Version.setText(self.trans(f"PYAS V{self.pyas_version} (ML Engine)"))
        self.ui.GUI_Made_title.setText(self.trans("介面製作:"))
        self.ui.GUI_Made_Name.setText(self.trans("mtkiao"))
        self.ui.Core_Made_title.setText(self.trans("核心製作:"))
        self.ui.Core_Made_Name.setText(self.trans("87owo"))
        self.ui.Testers_title.setText(self.trans("測試人員:"))
        self.ui.Testers_Name.setText(self.trans("87owo"))
        self.ui.PYAS_URL_title.setText(self.trans("官方網站:"))
        self.ui.PYAS_URL.setText(self.trans("<html><head/><body><p><a href=\"https://github.com/87owo/PYAS\"><span style=\" text-decoration: underline; color:#000000;\">https://github.com/87owo/PYAS</span></a></p></body></html>"))
        self.ui.high_sensitivity_title.setText(self.trans("高靈敏度模式"))
        self.ui.high_sensitivity_illustrate.setText(self.trans("啟用此選項可以提高引擎的靈敏度"))
        self.ui.high_sensitivity_switch_Button.setText(self.trans(self.ui.high_sensitivity_switch_Button.text()))
        self.ui.cloud_services_title.setText(self.trans("雲端掃描服務"))
        self.ui.cloud_services_illustrate.setText(self.trans("啟用此選項可以連接雲端掃描服務"))
        self.ui.cloud_services_switch_Button.setText(self.trans(self.ui.cloud_services_switch_Button.text()))
        self.ui.Add_White_list_title.setText(self.trans("增加到白名單"))
        self.ui.Add_White_list_illustrate.setText(self.trans("此選項可以選擇檔案並增加到白名單"))
        self.ui.Add_White_list_Button.setText(self.trans(self.ui.Add_White_list_Button.text()))
        self.ui.Add_White_list_Button.setText(self.trans("選擇"))
        self.ui.Theme_title.setText(self.trans("顯色主題"))
        self.ui.Theme_illustrate.setText(self.trans("請選擇主題"))
        self.ui.Theme_White.setText(self.trans("白色主題"))
        self.ui.Theme_Black.setText(self.trans("黑色主題"))
        self.ui.Theme_Yellow.setText(self.trans("黃色主題"))
        self.ui.Theme_Red.setText(self.trans("紅色主題"))
        self.ui.Theme_Green.setText(self.trans("綠色主題"))
        self.ui.Theme_Blue.setText(self.trans("藍色主題"))
        self.ui.Setting_Back.setText(self.trans("返回"))
        self.ui.Language_title.setText(self.trans("顯示語言"))
        self.ui.Language_illustrate.setText(self.trans("請選擇語言"))
        self.ui.License_terms_title.setText(self.trans("許可條款:"))

    def change_theme(self):
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

    def change_animation(self,widget):
        x, y = 170, widget.pos().y()
        self.anim = QPropertyAnimation(widget, b"geometry")
        widget.setGeometry(QRect(x - 100,y, 671,481))
        self.anim.setKeyValueAt(0.2, QRect(x - 60,y,671,481))
        self.anim.setKeyValueAt(0.4, QRect(x - 10,y,671,481))
        self.anim.setKeyValueAt(0.7, QRect(x - 3,y,671,481))
        self.anim.setKeyValueAt(1, QRect(x,y,671,481))
        self.anim.start()

    def change_animation_2(self,nx,ny):
        x, y = self.ui.label.pos().x(), self.ui.label.pos().y()
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

    def change_animation_3(self,widget,time):
        self.opacity = QGraphicsOpacityEffect()
        self.opacity.setOpacity(0)
        self.opacity.i = self.opacity.opacity()
        widget.setGraphicsEffect(self.opacity)
        widget.setAutoFillBackground(True)
        self.timer = QTimer()
        self.timer.timeout.connect(self.timeout)
        self.timer.start(2)

    def timeout(self):
        if self.opacity.i < 1:
            self.opacity.i += 0.02
            self.opacity.setOpacity(self.opacity.i)
        else:
            self.timer.stop()

    def change_animation_4(self,widget,time,ny,ny2):
        x, y = widget.pos().x(), widget.pos().y()
        self.anim4 = QPropertyAnimation(widget, b"geometry")
        self.anim4.setDuration(time)
        self.anim4.setStartValue(QRect(x, y, 141, ny))
        self.anim4.setEndValue(QRect(x, y, 141, ny2))
        self.anim4.start()

    def change_animation_5(self,widget,x,y,nx,ny):
        self.anim = QPropertyAnimation(widget, b"geometry")
        widget.setGeometry(QRect(x,y - 45, nx,ny))
        self.anim.setKeyValueAt(0.2, QRect(x,y - 30,nx,ny))
        self.anim.setKeyValueAt(0.4, QRect(x,y - 10,nx,ny))
        self.anim.setKeyValueAt(0.7, QRect(x,y - 3,nx,ny))
        self.anim.setKeyValueAt(1, QRect(x,y,nx,ny))
        self.anim.start()

    def change_state_widget(self):
        if self.ui.State_widget.isHidden():
            self.change_animation_2(20,50)
            self.change_animation_3(self.ui.State_widget,0.5)
            self.change_animation(self.ui.State_widget)
            self.ui.State_widget.show()
            self.ui.Virus_Scan_widget.hide()
            self.ui.Tools_widget.hide()
            self.ui.Protection_widget.hide()
            self.ui.Process_widget.hide()
            self.ui.About_widget.hide()
            self.ui.Setting_widget.hide()

    def change_scan_widget(self):
        if self.ui.Virus_Scan_widget.isHidden():
            self.change_animation_2(20,168)
            self.change_animation_3(self.ui.Virus_Scan_widget,0.5)
            self.change_animation(self.ui.Virus_Scan_widget)
            self.ui.State_widget.hide()
            self.ui.Virus_Scan_widget.show()
            self.ui.Tools_widget.hide()
            self.ui.Protection_widget.hide()
            self.ui.Process_widget.hide()
            self.ui.About_widget.hide()
            self.ui.Setting_widget.hide()

    def change_tools_widget(self):
        if self.ui.Tools_widget.isHidden():
            self.change_animation_2(20,285)
            self.change_animation_3(self.ui.Tools_widget,0.5)
            self.change_animation(self.ui.Tools_widget)
            self.ui.State_widget.hide()
            self.ui.Virus_Scan_widget.hide()
            self.ui.Tools_widget.show()
            self.ui.Protection_widget.hide()
            self.ui.Process_widget.hide()
            self.ui.About_widget.hide()
            self.ui.Setting_widget.hide()

    def change_protect_widget(self):
        if self.ui.Protection_widget.isHidden():
            self.change_animation_2(20,405)
            self.change_animation_3(self.ui.Protection_widget,0.5)
            self.change_animation(self.ui.Protection_widget)
            self.ui.State_widget.hide()
            self.ui.Virus_Scan_widget.hide()
            self.ui.Tools_widget.hide()
            self.ui.Protection_widget.show()
            self.ui.Process_widget.hide()
            self.ui.About_widget.hide()
            self.ui.Setting_widget.hide()

    def change_tools(self,widget):
        self.ui.Tools_widget.hide()
        self.ui.Setting_widget.hide()
        self.ui.About_widget.hide()
        if widget == self.ui.Process_widget:
            self.Process_Timer.start(0)
        elif widget == self.ui.System_Info_widget:
            self.System_Info_update()
        self.change_animation_3(widget,0.5)
        self.change_animation(widget)
        widget.show()

    def back_to_tools(self,widget):
        widget.hide()
        if widget == self.ui.Process_widget:
            self.Process_Timer.stop()
        self.change_animation_3(self.ui.Tools_widget,0.5)
        self.change_animation(self.ui.Tools_widget)
        self.ui.Tools_widget.show()

    def mousePressEvent(self, event):
        def update_opacity():
            if self.pyas_opacity > 80 and self.m_flag == True:
                self.pyas_opacity -= 1
                self.setWindowOpacity(self.pyas_opacity/100)
            else:
                self.timer.stop()
        x, y = event.x(), event.y()
        if event.button()==Qt.LeftButton and x >= 10 and x <= 841 and y >= 10 and y <= 49:
            self.m_flag = True
            self.m_Position=event.globalPos()-self.pos()
            event.accept()
            self.timer = QTimer()
            self.timer.timeout.connect(update_opacity)
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
        def update_opacity():
            if self.pyas_opacity < 100 and self.m_flag == False:
                self.pyas_opacity += 1
                self.setWindowOpacity(self.pyas_opacity/100)
            else:
                self.timer.stop()
        self.m_flag = False
        self.setCursor(QCursor(Qt.ArrowCursor))
        self.timer = QTimer()
        self.timer.timeout.connect(update_opacity)
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
        def update_opacity():
            if self.pyas_opacity <= 100:
                self.pyas_opacity += 1
                self.setWindowOpacity(self.pyas_opacity/100)
            else:
                self.timer.stop()
        self.show()
        self.pyas_opacity = 0
        self.timer = QTimer()
        self.timer.timeout.connect(update_opacity)
        self.timer.start(2)

    def hide_pyas_ui(self):
        def update_opacity():
            if self.pyas_opacity >= 0:
                self.pyas_opacity -= 1
                self.setWindowOpacity(self.pyas_opacity/100)
            else:
                self.timer.stop()
                self.hide()
        self.timer = QTimer()
        self.timer.timeout.connect(update_opacity)
        self.timer.start(2)

    def showMinimized(self):
        self.hide_pyas_ui()
        self.send_notify(self.trans("PYAS 已最小化到系統托盤圖標"))

    def closeEvent(self, event):
        if QMessageBox.warning(self,self.trans("警告"),self.trans("您確定要退出 PYAS 和所有防護嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
            self.virus_scan_break()
            event.accept()
        else:
            event.ignore()

    def bug_event(self, text):
        try:
            print(f"[Error] {text}")
            QMessageBox.critical(self,self.trans("錯誤"), text, QMessageBox.Ok)
        except:
            pass

    def send_notify(self,text):
        try:
            now_time = time.strftime('%Y/%m/%d %H:%M:%S')
            self.ui.State_output.append(f"[{now_time}] {text}")
            self.tray_icon.showMessage(now_time, text, 5000)
        except:
            pass

    def show_menu(self):
        self.WindowMenu = QMenu()
        Main_Settings = QAction(self.trans("設定"),self)
        Main_About = QAction(self.trans("關於"),self)
        self.WindowMenu.addAction(Main_Settings)
        self.WindowMenu.addAction(Main_About)
        Qusetion = self.WindowMenu.exec_(self.ui.Menu_Button.mapToGlobal(QPoint(0, 30)))
        if Qusetion == Main_About and self.ui.About_widget.isHidden():
            self.ui.About_widget.show()
            self.ui.About_widget.raise_()
            self.ui.Navigation_Bar.raise_()
            self.ui.Window_widget.raise_()
            self.change_animation_3(self.ui.About_widget,0.5)
            self.change_animation_5(self.ui.About_widget,170,50,671,481)
            self.setting_back()
        if Qusetion == Main_Settings and self.ui.Setting_widget.isHidden():
            self.ui.Setting_widget.show()
            self.ui.About_widget.hide()
            self.ui.Setting_widget.raise_()
            self.ui.Window_widget.raise_()
            self.change_animation_3(self.ui.Setting_widget,0.5)
            self.change_animation_5(self.ui.Setting_widget,10,50,831,481)

    def change_sensitive(self):
        sw_state = self.ui.high_sensitivity_switch_Button.text()
        if sw_state == self.trans("已開啟"):
            self.high_sensitivity = 0
            self.json["high_sensitivity"] = 0
            self.ui.high_sensitivity_switch_Button.setText(self.trans("已關閉"))
            self.ui.high_sensitivity_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,20,20,30);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,20,20,50);}""")
        elif QMessageBox.warning(self,self.trans("警告"),self.trans("此選項可能會誤報檔案，您確定要開啟嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
            self.high_sensitivity = 1
            self.json["high_sensitivity"] = 1
            self.ui.high_sensitivity_switch_Button.setText(self.trans("已開啟"))
            self.ui.high_sensitivity_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")
        self.write_config(self.json)

    def change_cloud_service(self):
        sw_state = self.ui.cloud_services_switch_Button.text()
        if sw_state == self.trans("已關閉"):
            self.cloud_services = 1
            self.json["cloud_services"] = 1
            self.ui.cloud_services_switch_Button.setText(self.trans("已開啟"))
            self.ui.cloud_services_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")
        elif sw_state == self.trans("已開啟"):
            self.cloud_services = 0
            self.json["cloud_services"] = 0
            self.ui.cloud_services_switch_Button.setText(self.trans("已關閉"))
            self.ui.cloud_services_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,20,20,30);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,20,20,50);}""")
        self.write_config(self.json)

    def init_state_safe(self):
        try:
            self.safe = True
            self.ui.State_icon.setPixmap(QPixmap(":/icon/Check.png"))
            self.ui.State_title.setText(self.trans("此裝置已受到防護"))
        except:
            pass

    def init_state_unsafe(self):
        try:
            self.safe = False
            self.ui.State_icon.setPixmap(QPixmap(":/icon/Close.png"))
            self.ui.State_title.setText(self.trans("此裝置當前不安全"))
        except:
            pass

    def init_scan(self):
        try:
            self.ui.Virus_Scan_text.setText(self.trans("正在初始化中"))
            QApplication.processEvents()
            for file in self.virus_list:
                self.unlock_file(file)
            self.scan_file = True
            self.init_virus_list()
            self.ui.Virus_Scan_Solve_Button.hide()
            self.ui.Virus_Scan_choose_widget.hide()
            self.ui.Virus_Scan_choose_Button.hide()
            self.ui.Virus_Scan_Break_Button.show()
            self.ui.Virus_Scan_output.clear()
        except Exception as e:
            self.bug_event(e)

    def Virus_Scan_output_menu(self, point):
        def copyPathFunc():
            item_row = False
            for i in self.ui.Virus_Scan_output.selectedIndexes():
                item_row = self.virus_list[i.row()]
            if item_row:
                pyperclip.copy(item_row)
        menu = QMenu()
        copyPath = menu.addAction(self.trans("複製路徑"))
        copyPath.triggered.connect(lambda: copyPathFunc())
        menu.exec_(self.ui.Virus_Scan_output.mapToGlobal(point))

    def lock_file(self, file):
        try:
            self.virus_lock[file] = os.open(file, os.O_RDWR)
            msvcrt.locking(self.virus_lock[file], msvcrt.LK_NBLCK, 0)
        except:
            pass

    def unlock_file(self, file):
        try:
            msvcrt.locking(self.virus_lock[file], msvcrt.LK_UNLCK, 0)
            os.close(self.virus_lock[file])
        except:
            pass

    def virus_solve(self):
        try:
            self.ui.Virus_Scan_Solve_Button.hide()
            for file in self.virus_list:
                try:
                    if self.ui.Virus_Scan_output.findItems(file, Qt.MatchContains)[0].checkState() == Qt.Checked:
                        self.ui.Virus_Scan_text.setText(self.trans("正在刪除: ")+file)
                        QApplication.processEvents()
                        self.unlock_file(file)
                        os.remove(file)
                    else:
                        self.unlock_file(file)
                except:
                    continue
            self.init_state_safe()
            self.init_virus_list()
            self.ui.Virus_Scan_output.clear()
            self.ui.Virus_Scan_text.setText(self.trans("成功: 刪除成功"))
        except Exception as e:
            self.bug_event(e)

    def write_scan(self, state, file):
        try:
            self.lock_file(file)
            self.virus_list.append(file)
            self.virus_list_ui.append(f"[{state}] {file}")
            item = QListWidgetItem()
            item.setText(f"[{state}] {file}")
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked)
            self.ui.Virus_Scan_output.addItem(item)
        except:
            pass

    def answer_scan(self):
        try:
            if self.virus_list:
                self.init_state_unsafe()
                self.ui.Virus_Scan_Solve_Button.show()
                self.ui.Virus_Scan_Break_Button.hide()
                self.ui.Virus_Scan_choose_Button.show()
                text = self.trans(f"當前發現 {len(self.virus_list)} 個病毒")
            else:
                self.virus_scan_break()
                self.init_state_safe()
                text = self.trans("當前未發現病毒")
            self.ui.Virus_Scan_text.setText(text)
            self.send_notify(text)
            gc.collect()
        except Exception as e:
            self.bug_event(e)

    def virus_scan_break(self):
        self.scan_file = False
        self.ui.Virus_Scan_Break_Button.hide()
        self.ui.Virus_Scan_choose_Button.show()
        self.ui.Virus_Scan_text.setText(self.trans("請選擇掃描方式"))

    def virus_scan_menu(self):
        if self.ui.Virus_Scan_choose_widget.isHidden():
            self.ui.Virus_Scan_choose_widget.show()
            self.change_animation_4(self.ui.Virus_Scan_choose_widget,100,0,101)
        else:
            self.ui.Virus_Scan_choose_widget.hide()

    def file_scan(self):
        try:
            file = str(QFileDialog.getOpenFileName(self,self.trans("病毒掃描"),"C:/")[0])
            if file and file not in self.whitelist:
                self.init_scan()
                self.start_scan(file)
                self.answer_scan()
        except Exception as e:
            self.bug_event(e)
            self.virus_scan_break()

    def path_scan(self):
        try:
            path = str(QFileDialog.getExistingDirectory(self,self.trans("病毒掃描"),"C:/"))
            if path:
                self.init_scan()
                self.traverse_path(path)
                self.answer_scan()
        except Exception as e:
            self.bug_event(e)
            self.virus_scan_break()

    def disk_scan(self):
        try:
            self.init_scan()
            for d in range(26):
                if os.path.exists(f"{chr(65+d)}:/"):
                    self.traverse_path(f"{chr(65+d)}:/")
            self.answer_scan()
        except Exception as e:
            self.bug_event(e)
            self.virus_scan_break()

    def start_scan(self, file):
        try:
            file_type = str(f".{file.split('.')[-1]}").lower()
            if self.high_sensitivity and file != self.pyas:
                if self.api_scan(file):
                    self.write_scan(self.trans("惡意"),file)
                elif self.pe_scan(file):
                    self.write_scan(self.trans("可疑"),file)
            elif file_type in slist and self.sign_scan(file):
                if self.api_scan(file):
                    self.write_scan(self.trans("惡意"),file)
                elif self.pe_scan(file):
                    self.write_scan(self.trans("可疑"),file)
        except:
            pass

    def traverse_path(self,path):
        for fd in os.listdir(path):
            try:
                file = str(os.path.join(path,fd)).replace("\\", "/")
                if self.scan_file == False:
                    break
                elif ":/Windows" in file:
                    continue
                elif os.path.isdir(file):
                    self.traverse_path(file)
                elif file not in self.whitelist:
                    self.ui.Virus_Scan_text.setText(self.trans(f"正在掃描: ")+file)
                    QApplication.processEvents()
                    self.start_scan(file)
                gc.collect()
            except:
                pass

    def api_scan(self, file):
        try:
            if self.cloud_services == 1:
                with open(file, "rb") as f:
                    text = str(hashlib.md5(f.read()).hexdigest())
                strBody = f'-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="md5s"\r\n\r\n{text}\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="format"\r\n\r\nXML\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="product"\r\n\r\n360zip\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="combo"\r\n\r\n360zip_main\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="v"\r\n\r\n2\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="osver"\r\n\r\n5.1\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="vk"\r\n\r\na03bc211\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="mid"\r\n\r\n8a40d9eff408a78fe9ec10a0e7e60f62\r\n-------------------------------7d83e2d7a141e--'
                response = requests.post('http://qup.f.360.cn/file_health_info.php', data=strBody, timeout=3)
                return response.status_code == 200 and float(xmlet.fromstring(response.text).find('.//e_level').text) > 50
            return False
        except:
            return False

    def sign_scan(self, file):
        try:
            with pefile.PE(file, fast_load=True) as pe:
                return pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].VirtualAddress == 0
        except:
            return True

    def pe_scan(self, file):
        try:
            fn = []
            with pefile.PE(file) as pe:
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for func in entry.imports:
                        try:
                            fn.append(str(func.name, "utf-8"))
                        except:
                            pass
            max_vfl = []
            for vfl in function_list:
                QApplication.processEvents()
                max_vfl.append(len(set(fn)&set(vfl))/len(set(fn)|set(vfl)))
            if self.high_sensitivity and max(max_vfl) == 1.0:
                return True
            elif "_CorExeMain" not in fn and max(max_vfl) == 1.0:
                return True
            return False
        except:
            return False

    def repair_system(self):
        try:
            if QMessageBox.warning(self,self.trans("警告"),self.trans("您確定要修復系統檔案嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
                self.repair_system_wallpaper()
                self.repair_system_restrict()
                self.repair_system_file_type()
                self.repair_system_file_icon()
                self.repair_system_image()
                QMessageBox.information(self,self.trans("成功"),self.trans("修復系統檔案成功"),QMessageBox.Ok)
        except Exception as e:
            self.bug_event(e)

    def repair_system_file_icon(self):
        try:
            key = win32api.RegOpenKey(win32con.HKEY_CLASSES_ROOT, 'exefile', 0, win32con.KEY_ALL_ACCESS)
            win32api.RegSetValue(key, 'DefaultIcon', win32con.REG_SZ, '%1')
        except:
            pass
        try:
            key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, r'SOFTWARE\Classes\exefile', 0, win32con.KEY_ALL_ACCESS)
            win32api.RegSetValue(key, 'DefaultIcon', win32con.REG_SZ, '%1')
        except:
            pass

    def repair_system_image(self):
        try:
            key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',0,win32con.KEY_ALL_ACCESS | win32con.WRITE_OWNER)
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
            key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, r'SOFTWARE\Classes', 0, win32con.KEY_ALL_ACCESS)
            for ext, value in data:
                win32api.RegSetValue(key, ext, win32con.REG_SZ, value)
            win32api.RegCloseKey(key)
            key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, r'SOFTWARE\Classes', 0, win32con.KEY_ALL_ACCESS)
            for ext, value in data:
                try:
                    win32api.RegSetValue(key, ext, win32con.REG_SZ, value)
                    keyopen = win32api.RegOpenKey(key, ext + r'\shell\open', 0, win32con.KEY_ALL_ACCESS)
                    win32api.RegSetValue(keyopen, 'command', win32con.REG_SZ, '"%1" %*')
                    win32api.RegCloseKey(keyopen)
                except:
                    pass
            win32api.RegCloseKey(key)
            key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts', 0, win32con.KEY_ALL_ACCESS)
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

    def repair_system_restrict(self):
        try:
            Permission = ["NoControlPanel", "NoDrives", "NoFileMenu", "NoFind", "NoRealMode", "NoRecentDocsMenu","NoSetFolders",
            "NoSetFolderOptions", "NoViewOnDrive", "NoClose", "NoRun", "NoDesktop", "NoLogOff", "NoFolderOptions", "RestrictRun","DisableCMD",
            "NoViewContexMenu", "HideClock", "NoStartMenuMorePrograms", "NoStartMenuMyGames", "NoStartMenuMyMusic" "NoStartMenuNetworkPlaces",
            "NoStartMenuPinnedList", "NoActiveDesktop", "NoSetActiveDesktop", "NoActiveDesktopChanges", "NoChangeStartMenu", "ClearRecentDocsOnExit",
            "NoFavoritesMenu", "NoRecentDocsHistory", "NoSetTaskbar", "NoSMHelp", "NoTrayContextMenu", "NoViewContextMenu", "NoWindowsUpdate",
            "NoWinKeys", "StartMenuLogOff", "NoSimpleNetlDList", "NoLowDiskSpaceChecks", "DisableLockWorkstation", "NoManageMyComputerVerb",
            "DisableTaskMgr", "DisableRegistryTools", "DisableChangePassword", "Wallpaper", "NoComponents", "NoAddingComponents", "Restrict_Run"]
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",0,win32con.KEY_ALL_ACCESS),"Explorer")
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",0,win32con.KEY_ALL_ACCESS),"Explorer")
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",0,win32con.KEY_ALL_ACCESS),"System")
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",0,win32con.KEY_ALL_ACCESS),"System")
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",0,win32con.KEY_ALL_ACCESS),"ActiveDesktop")
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,r"SOFTWARE\Policies\Microsoft\Windows",0,win32con.KEY_ALL_ACCESS),"System")
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,r"SOFTWARE\Policies\Microsoft\Windows",0,win32con.KEY_ALL_ACCESS),"System")
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,r"Software\Policies\Microsoft",0,win32con.KEY_ALL_ACCESS),"MMC")
            win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,r"Software\Policies\Microsoft\MMC",0,win32con.KEY_ALL_ACCESS),"{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}")
            keys = [win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",0,win32con.KEY_ALL_ACCESS),
            win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",0,win32con.KEY_ALL_ACCESS),
            win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",0,win32con.KEY_ALL_ACCESS),
            win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",0,win32con.KEY_ALL_ACCESS),
            win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop",0,win32con.KEY_ALL_ACCESS),
            win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,r"SOFTWARE\Policies\Microsoft\Windows\System",0,win32con.KEY_ALL_ACCESS),
            win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,r"SOFTWARE\Policies\Microsoft\Windows\System",0,win32con.KEY_ALL_ACCESS),
            win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,r"Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}",0,win32con.KEY_ALL_ACCESS)]
            for key in keys:
                for i in Permission:
                    try:
                        win32api.RegDeleteValue(key,i)
                        self.proc.kill()
                        self.send_notify(self.trans("惡意行為攔截: ")+self.proc.name())
                    except:
                        pass
                win32api.RegCloseKey(key)
        except:
            pass

    def repair_system_wallpaper(self):
        try:
            key = win32api.RegOpenKeyEx(win32con.HKEY_CURRENT_USER, r"Control Panel\Desktop", 0, win32con.KEY_SET_VALUE)
            win32api.RegSetValueEx(key, "Wallpaper", 0, win32con.REG_SZ, 'C:/Windows/web/wallpaper/windows/img0.jpg')
            win32api.RegCloseKey(key)
            win32gui.SystemParametersInfo(win32con.SPI_SETDESKWALLPAPER, 'C:/Windows/web/wallpaper/windows/img0.jpg', win32con.SPIF_SENDCHANGE)
        except:
            pass

    def clean_system(self):
        try:
            if QMessageBox.warning(self,self.trans("警告"),self.trans("您確定要清理系統垃圾嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
                self.total_deleted_size = 0
                self.traverse_temp(f"C:/Users/{os.getlogin()}/AppData/Local/Temp/")
                self.traverse_temp(f"C:/Windows/Temp/")
                self.traverse_temp(f"C:/$Recycle.Bin/")
                QMessageBox.information(self,self.trans("成功"),self.trans(f"成功清理了 {self.total_deleted_size} 位元的系統垃圾"),QMessageBox.Ok)
        except Exception as e:
            self.bug_event(e)

    def traverse_temp(self, path):
        for fd in os.listdir(path):
            try:
                file = str(os.path.join(path,fd)).replace("\\", "/")
                QApplication.processEvents()
                if os.path.isdir(file):
                    self.traverse_temp(file)
                else:
                    file_size = os.path.getsize(file)
                    os.remove(file)
                    self.total_deleted_size += file_size
            except:
                continue

    def add_white_list(self):
        try:
            file = str(QFileDialog.getOpenFileName(self,self.trans("增加到白名單"),"C:/")[0]).replace("\\", "/")
            if file and file not in self.whitelist:
                if QMessageBox.warning(self,self.trans("警告"),self.trans("您確定要增加到白名單嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
                    self.whitelist.append(file)
                    with open("C:/ProgramData/PYAS/Whitelist.ini", "a+", encoding="utf-8") as f:
                        f.write(f"{file}\n")
                    QMessageBox.information(self,self.trans("成功"),self.trans(f"成功增加到白名單: ")+file,QMessageBox.Ok)
            elif file and QMessageBox.warning(self,self.trans("警告"),self.trans("您確定要取消增加到白名單嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
                self.whitelist.remove(file)
                with open("C:/ProgramData/PYAS/Whitelist.ini", "w", encoding="utf-8") as f:
                    for white_file in self.whitelist:
                        f.write(f'{white_file}\n')
                QMessageBox.information(self,self.trans("成功"),self.trans(f"成功取消增加到白名單: ")+file,QMessageBox.Ok)
        except Exception as e:
            self.bug_event(e)

    def get_software_window(self):
        try:
            self.block_window = False
            if QMessageBox.warning(self,self.trans("警告"),self.trans("請選擇要攔截的軟體彈窗"),QMessageBox.Yes|QMessageBox.No) == 16384:
                while not self.block_window:
                    window_name = str(win32gui.GetWindowText(win32gui.GetForegroundWindow()))
                    QApplication.processEvents()
                    if window_name not in ["","PYAS",self.trans("警告")]:
                        if window_name not in self.blocklist:
                            if QMessageBox.warning(self,self.trans("警告"),self.trans(f"您確定要攔截 {window_name} 嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
                                self.blocklist.append(window_name)
                                with open("C:/ProgramData/PYAS/Blocklist.ini", "a+", encoding="utf-8") as f:
                                    f.write(f'{window_name}\n')
                                QMessageBox.information(self,self.trans("成功"),self.trans(f"成功增加到彈窗攔截: ")+window_name,QMessageBox.Ok)
                        elif QMessageBox.warning(self,self.trans("警告"),self.trans(f"您確定要取消攔截 {window_name} 嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
                            self.blocklist.remove(window_name)
                            with open("C:/ProgramData/PYAS/Blocklist.ini", "w", encoding="utf-8") as f:
                                for block_name in self.blocklist:
                                    f.write(f'{block_name}\n')
                            QMessageBox.information(self,self.trans("成功"),self.trans(f"成功取消彈窗攔截: ")+window_name,QMessageBox.Ok)
                        self.block_window = True
            self.block_window_init()
        except Exception as e:
            self.bug_event(e) 

    def block_window_init(self):
        self.block_window = True
        Thread(target=self.block_software_window, daemon=True).start()

    def block_software_window(self):
        while self.block_window:
            try:
                time.sleep(0.5)
                for window_name in self.blocklist:
                    win32gui.PostMessage(win32gui.FindWindow(None, window_name), 274, 61536, 0)
            except:
                pass

    def repair_network(self):
        try:
            if QMessageBox.warning(self,self.trans("警告"),self.trans("您確定要修復系統網路嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
                os.system("netsh winsock reset")
                if QMessageBox.warning(self,self.trans("警告"),self.trans("使用此選項需要重啟，您確定要重啟嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
                    os.system("shutdown -r -t 0")
        except Exception as e:
            self.bug_event(e)

    def setting_back(self):
        self.ui.Navigation_Bar.show()
        self.ui.Setting_widget.hide()

    def process_list(self):
        try:
            self.Process_list_app = []
            self.Process_list_app_pid = []
            for p in psutil.process_iter():
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
            self.bug_event(e)

    def process_list_menu(self,pos):
        try:
            for i in self.ui.Process_list.selectedIndexes():
                self.pid = self.Process_list_all_pid[i.row()]
            self.Process_popMenu = QMenu()
            self.kill_Process = QAction(self.trans("結束進程"),self)
            self.Process_popMenu.addAction(self.kill_Process)
            if self.Process_popMenu.exec_(self.ui.Process_list.mapToGlobal(pos)) == self.kill_Process:
                for p in psutil.process_iter():
                    if p.pid == self.pid:
                        p.kill()
        except:
            pass

    def protect_proc_init(self):
        if self.ui.Protection_switch_Button.text() == self.trans("已開啟"):
            self.proc_protect = False
            self.ui.Protection_switch_Button.setText(self.trans("已關閉"))
            self.ui.Protection_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,20,20,30);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,20,20,50);}""")
        else:
            self.proc_protect = True
            self.ui.Protection_switch_Button.setText(self.trans("已開啟"))
            self.ui.Protection_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")
            Thread(target=self.protect_proc_thread, daemon=True).start()

    def protect_file_init(self):
        if self.ui.Protection_switch_Button_2.text() == self.trans("已開啟"):
            self.file_protect = False
            self.ui.Protection_switch_Button_2.setText(self.trans("已關閉"))
            self.ui.Protection_switch_Button_2.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,20,20,30);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,20,20,50);}""")
        else:
            self.file_protect = True
            self.ui.Protection_switch_Button_2.setText(self.trans("已開啟"))
            self.ui.Protection_switch_Button_2.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")
            Thread(target=self.protect_file_thread, daemon=True).start()

    def protect_boot_init(self):
        if self.ui.Protection_switch_Button_3.text() == self.trans("已開啟"):
            self.mbr_protect = False
            self.ui.Protection_switch_Button_3.setText(self.trans("已關閉"))
            self.ui.Protection_switch_Button_3.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,20,20,30);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,20,20,50);}""")
        else:
            self.mbr_protect = True
            self.ui.Protection_switch_Button_3.setText(self.trans("已開啟"))
            self.ui.Protection_switch_Button_3.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")
            Thread(target=self.protect_boot_thread, daemon=True).start()

    def protect_reg_init(self):
        if self.ui.Protection_switch_Button_4.text() == self.trans("已開啟"):
            self.reg_protect = False
            self.ui.Protection_switch_Button_4.setText(self.trans("已關閉"))
            self.ui.Protection_switch_Button_4.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,20,20,30);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,20,20,50);}""")
        else:
            self.reg_protect = True
            self.ui.Protection_switch_Button_4.setText(self.trans("已開啟"))
            self.ui.Protection_switch_Button_4.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")
            Thread(target=self.protect_reg_thread, daemon=True).start()

    def protect_net_init(self):
        if self.ui.Protection_switch_Button_5.text() == self.trans("已開啟"):
            self.net_protect = False
            self.ui.Protection_switch_Button_5.setText(self.trans("已關閉"))
            self.ui.Protection_switch_Button_5.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,20,20,30);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,20,20,50);}""")
        else:
            self.net_protect = True
            self.ui.Protection_switch_Button_5.setText(self.trans("已開啟"))
            self.ui.Protection_switch_Button_5.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")
            Thread(target=self.protect_net_thread, daemon=True).start()

    def protect_proc_thread(self):
        existing_processes = set()
        for p in psutil.process_iter():
            if p.pid not in existing_processes:
                existing_processes.add(p.pid)
        while self.proc_protect:
            time.sleep(0.05)
            for p in psutil.process_iter():
                try:
                    if p.pid not in existing_processes:
                        existing_processes.add(p.pid)
                        psutil.Process(p.pid).suspend()
                        name, file, cmd = p.name(), p.exe().replace("\\", "/"), p.cmdline()
                        if self.protect_proc_scan(name, file, cmd):
                            p.kill()
                            self.send_notify(self.trans("惡意軟體攔截: ")+file)
                        elif ":/Windows" not in file and self.sign_scan(file):
                            self.proc = p
                        psutil.Process(p.pid).resume()
                        gc.collect()
                except:
                    pass

    def protect_proc_scan(self, name, file, cmd):
        try:
            if file != self.pyas and file not in self.whitelist:
                if "powershell" in name:
                    file = str(cmd[-1].split("'")[-2])
                elif "cmd.exe" in name:
                    file = str(" ".join(cmd[2:]))
                elif ":/Windows" in file:
                    file = str(cmd[-1])
                elif ":/Program" in file:
                    file = str(cmd[-1])
                return self.api_scan(file) or self.pe_scan(file)
            return False
        except:
            pass

    def protect_file_thread(self):
        hDir = win32file.CreateFile("C:/Users/",win32con.GENERIC_READ,win32con.FILE_SHARE_READ|win32con.FILE_SHARE_WRITE|win32con.FILE_SHARE_DELETE,None,win32con.OPEN_EXISTING,win32con.FILE_FLAG_BACKUP_SEMANTICS,None)
        self.ransom_block = False
        while self.file_protect:
            for action, file in win32file.ReadDirectoryChangesW(hDir,1024,True,win32con.FILE_NOTIFY_CHANGE_FILE_NAME|win32con.FILE_NOTIFY_CHANGE_DIR_NAME|win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES|win32con.FILE_NOTIFY_CHANGE_SIZE|win32con.FILE_NOTIFY_CHANGE_LAST_WRITE|win32con.FILE_NOTIFY_CHANGE_SECURITY,None,None):
                try:
                    if action == 2 and str(f".{file.split('.')[-1]}").lower() in alist:
                        if self.ransom_block and "AppData" not in file:
                            self.proc.kill()
                            self.ransom_block = False
                            self.send_notify(self.trans("勒索軟體攔截: ")+self.proc.name())
                        self.ransom_block = True
                except:
                    pass

    def protect_boot_thread(self):
        while self.mbr_protect and self.mbr_value:
            try:
                time.sleep(0.5)
                with open(r"\\.\PhysicalDrive0", "r+b") as f:
                    if self.mbr_value[510:512] != b'\x55\xAA':
                        self.proc.kill()
                        self.send_notify(self.trans("惡意行為攔截: ")+self.proc.name())
                    elif f.read(512) != self.mbr_value:
                        f.seek(0)
                        f.write(self.mbr_value)
                        self.proc.kill()
                        self.send_notify(self.trans("惡意行為攔截: ")+self.proc.name())
            except:
                pass

    def protect_reg_thread(self):
        while self.reg_protect:
            try:
                time.sleep(0.5)
                self.repair_system_image()
                self.repair_system_restrict()
                self.repair_system_file_type()
                self.repair_system_file_icon()
            except:
                pass

    def protect_net_thread(self):
        while self.net_protect:
            try:
                time.sleep(0.5)
                for conn in self.proc.connections():
                    if socket.gethostbyname(socket.gethostname()) == conn.laddr.ip:
                        self.proc.kill()
                        self.send_notify(self.trans("網路通訊攔截: ")+self.proc.name())
            except:
                pass

if __name__ == '__main__':
    QCoreApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    QGuiApplication.setAttribute(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    MainWindow_Controller()
    sys.exit(app.exec_())
