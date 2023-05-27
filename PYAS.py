####################################################################################
# Coding Python 3.11 UTF-8 [64-bit] (Python IDLE)
#
# PYAS Web: https://pyantivirus.wixsite.com/pyas
# PYAS Git: https://github.com/87owo/PYAS
#
# Copyright© 2020-2023 87owo (PYAS Security)
####################################################################################

###################################### 加載模組 #####################################

import os, sys, time, json, socket, psutil
import requests, subprocess, cryptocode
import win32file, win32api, win32con
from pefile import PE, DIRECTORY_ENTRY
from hashlib import md5, sha1, sha256
from PYAS_Language import translations
from PYAS_Model import function_list
import xml.etree.ElementTree as ET
from threading import Thread
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5 import QtWidgets, QtGui, QtCore
from PYAS_UI import Ui_MainWindow

###################################### 主要程式 #####################################

class MainWindow_Controller(QtWidgets.QMainWindow):
    def __init__(self):
        super(MainWindow_Controller, self).__init__()
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.ui = Ui_MainWindow()
        self.create_library()
        self.tray_icon_start()
        self.ui.setupUi(self)
        self.init_config()
        self.init_config_ui()
        self.setup_control()
        self.show_pyas_ui()
        self.protect_start()

    def tray_icon_start(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon("Library/ICON.ico"))
        self.tray_icon.activated.connect(self.onTrayIconActivated)
        self.tray_icon.show()

    def protect_start(self):
        self.protect_threading_init()
        self.protect_threading_init_2()
        self.protect_threading_init_3()
        self.protect_threading_init_4()

    def create_library(self):
        try:
            if not os.path.exists("Library"):
                os.makedirs("Library")
        except:
            pass

    def writeConfig(self, config):
        try:
            with open("Library/PYAS.json", "w", encoding="utf-8") as f:
                f.write(json.dumps(config, indent=4, ensure_ascii=False))
        except Exception as e:
            self.pyas_bug_log(e)

    def init_config(self):
        self.Safe = True
        self.Virus_Scan = False
        self.pyas_opacity = 0
        self.ui.Theme_White.setChecked(True)
        self.mbr_value = self.init_config_mbr()
        self.pyasConfig = self.init_config_json()
        self.init_config_lang()
        self.init_config_sens()

    def init_config_mbr(self):
        try:
            with open(r"\\.\PhysicalDrive0", "r+b") as f:
                return f.read(512)
        except:
            return None

    def init_config_json(self):
        if not os.path.exists("Library/PYAS.json"):
            self.writeConfig({"language":"en_US","high_sensitivity":0,"cloud_services":1})
        with open("Library/PYAS.json", "r", encoding="utf-8") as f:
            return json.load(f)

    def init_config_lang(self):
        self.language = self.pyasConfig.get("language", "en_US")
        if self.language == "zh_TW":
            self.ui.Language_Traditional_Chinese.setChecked(True)
        elif self.language == "zh_CN":
            self.ui.Language_Simplified_Chinese.setChecked(True)
        else:
            self.ui.Languahe_English.setChecked(True)
        self.lang_init_refresh()

    def init_config_sens(self):
        self.high_sensitivity = self.pyasConfig.get("high_sensitivity", 0)
        if self.high_sensitivity == 1:
            self.ui.high_sensitivity_switch_Button.setText(self.text_Translate("已開啟"))
            self.ui.high_sensitivity_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")
        self.cloud_services = self.pyasConfig.get("cloud_services", 1)
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
        self.ui.Virus_Scan_Solve_Button.clicked.connect(self.Virus_Solve)
        self.ui.Virus_Scan_choose_Button.clicked.connect(self.Virus_Scan_Choose_Menu)
        self.ui.Virus_Scan_Break_Button.clicked.connect(self.Virus_Scan_Break)
        self.ui.File_Scan_Button.clicked.connect(self.file_scan)
        self.ui.Path_Scan_Button.clicked.connect(self.path_scan)
        self.ui.Disk_Scan_Button.clicked.connect(self.disk_scan)
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
        self.ui.Repair_System_Files_Button.clicked.connect(self.Repair_System_Files)
        self.ui.Clean_System_Files_Button.clicked.connect(self.Clean_System_Files)
        self.ui.Enable_Safe_Mode_Button.clicked.connect(self.Enable_Safe_Mode)
        self.ui.Disable_Safe_Mode_Button.clicked.connect(self.Disable_Safe_Mode)
        self.ui.Delete_Private_File_Button.clicked.connect(self.Delete_Private_File)
        self.ui.Customize_CMD_Command_Run_Button.clicked.connect(self.Customize_CMD_Command)
        self.ui.Look_for_File_Run_Button.clicked.connect(self.find_file_input)
        self.ui.Encryption_Text_Run_Button.clicked.connect(self.Encryption_Text)
        self.ui.Decrypt_Text_Run_Button.clicked.connect(self.Decrypt_Text)
        self.ui.Change_Users_Password_Run_Button.clicked.connect(self.Change_Users_Password)
        self.ui.Internet_location_Query_Button.clicked.connect(self.Internet_location_Query)
        self.ui.Rework_Network_Configuration_Button.clicked.connect(self.reset_network)
        self.ui.Customize_REG_Command_Run_Button.clicked.connect(self.Customize_REG_Command)
        self.ui.Process_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.Process_list.customContextMenuRequested.connect(self.Process_list_Menu)
        self.ui.Protection_switch_Button.clicked.connect(self.protect_threading_init)
        self.ui.Protection_switch_Button_2.clicked.connect(self.protect_threading_init_2)
        self.ui.Protection_switch_Button_3.clicked.connect(self.protect_threading_init_3)
        self.ui.Protection_switch_Button_4.clicked.connect(self.protect_threading_init_4)
        self.ui.high_sensitivity_switch_Button.clicked.connect(self.high_sensitivity_switch)
        self.ui.cloud_services_switch_Button.clicked.connect(self.cloud_services_switch)
        self.ui.Language_Traditional_Chinese.clicked.connect(self.Change_language)
        self.ui.Language_Simplified_Chinese.clicked.connect(self.Change_language)
        self.ui.Languahe_English.clicked.connect(self.Change_language)
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

###################################### 語言翻譯 #####################################

    def Change_language(self):
        try:
            self.ui.State_output.clear()
            if self.ui.Language_Traditional_Chinese.isChecked():
                self.pyasConfig["language"] = "zh_TW"
                self.writeConfig(self.pyasConfig)
            elif self.ui.Language_Simplified_Chinese.isChecked():
                self.pyasConfig["language"] = "zh_CN"
                self.writeConfig(self.pyasConfig)
            else:
                self.pyasConfig["language"] = "en_US"
                self.writeConfig(self.pyasConfig)
            self.lang_init_refresh()
        except Exception as e:
            self.pyas_bug_log(e)

    def text_Translate(self, text):
        for k, v in translations.get(self.pyasConfig["language"], translations).items():
            text = text.replace(str(k), str(v))
        return text

    def lang_init_refresh(self):
        self.ui.State_title.setText(self.text_Translate("此裝置已受到防護" if self.Safe else "此裝置當前不安全"))
        self.ui.Window_title.setText(self.text_Translate(f"PYAS V{pyas_version} (安全密鑰錯誤)" if not self.pyas_key() else f"PYAS V{pyas_version}"))
        self.ui.PYAS_CopyRight.setText(self.text_Translate(f"Copyright© 2020-{max(int(time.strftime('%Y')), 2020)} 87owo (PYAS Security)"))
        self.ui.PYAE_Version.setText(self.text_Translate(f"PYAE V{pyae_version}"))
        self.ui.State_Button.setText(self.text_Translate("狀態"))
        self.ui.Virus_Scan_Button.setText(self.text_Translate("掃描"))
        self.ui.Tools_Button.setText(self.text_Translate("工具"))
        self.ui.Protection_Button.setText(self.text_Translate("防護"))
        self.ui.Virus_Scan_title.setText(self.text_Translate("病毒掃描"))
        self.ui.Virus_Scan_text.setText(self.text_Translate("請選擇掃描方式"))
        self.ui.Virus_Scan_choose_Button.setText(self.text_Translate("病毒掃描"))
        self.ui.File_Scan_Button.setText(self.text_Translate("檔案掃描"))
        self.ui.Path_Scan_Button.setText(self.text_Translate("路徑掃描"))
        self.ui.Disk_Scan_Button.setText(self.text_Translate("全盤掃描"))
        self.ui.Virus_Scan_Solve_Button.setText(self.text_Translate("立即刪除"))
        self.ui.Virus_Scan_Break_Button.setText(self.text_Translate("停止掃描"))
        self.ui.Protection_title.setText(self.text_Translate("進程防護"))
        self.ui.Protection_illustrate.setText(self.text_Translate("啟用此選項可以監控進程並攔截病毒"))
        self.ui.Protection_switch_Button.setText(self.text_Translate(self.ui.Protection_switch_Button.text()))
        self.ui.Protection_title_2.setText(self.text_Translate("檔案防護"))
        self.ui.Protection_illustrate_2.setText(self.text_Translate("啟用此選項可以刪除病毒檔案變更"))
        self.ui.Protection_switch_Button_2.setText(self.text_Translate(self.ui.Protection_switch_Button_2.text()))
        self.ui.Protection_title_3.setText(self.text_Translate("引導防護"))
        self.ui.Protection_illustrate_3.setText(self.text_Translate("啟用此選項可以修復系統引導分區"))
        self.ui.Protection_switch_Button_3.setText(self.text_Translate(self.ui.Protection_switch_Button_3.text()))
        self.ui.Protection_title_4.setText(self.text_Translate("註冊表防護"))
        self.ui.Protection_illustrate_4.setText(self.text_Translate("啟用此選項可以修復系統註冊表"))
        self.ui.Protection_switch_Button_4.setText(self.text_Translate(self.ui.Protection_switch_Button_4.text()))
        self.ui.State_log.setText(self.text_Translate("日誌:"))
        self.ui.System_Tools_Button.setText(self.text_Translate("系統工具"))
        self.ui.Privacy_Tools_Button.setText(self.text_Translate("隱私工具"))
        self.ui.Develop_Tools_Button.setText(self.text_Translate("開發工具"))
        self.ui.More_Tools_Button.setText(self.text_Translate("更多工具"))
        self.ui.More_Tools_Back_Button.setText(self.text_Translate("工具>"))
        self.ui.System_Process_Manage_Button.setText(self.text_Translate("系統進程管理"))
        self.ui.Repair_System_Files_Button.setText(self.text_Translate("系統檔案修復"))
        self.ui.Clean_System_Files_Button.setText(self.text_Translate("系統垃圾清理"))
        self.ui.Enable_Safe_Mode_Button.setText(self.text_Translate("啟用安全模式"))
        self.ui.Disable_Safe_Mode_Button.setText(self.text_Translate("禁用安全模式"))
        self.ui.System_Info_Button.setText(self.text_Translate("系統版本資訊"))
        self.ui.System_Tools_Back.setText(self.text_Translate("返回"))
        self.ui.Privacy_Tools_Back.setText(self.text_Translate("返回"))
        self.ui.Delete_Private_File_Button.setText(self.text_Translate("隱私檔案粉碎"))
        self.ui.Develop_Tools_Back.setText(self.text_Translate("返回"))
        self.ui.Customize_REG_Command_Button.setText(self.text_Translate("自訂註冊表"))
        self.ui.Customize_CMD_Command_Button.setText(self.text_Translate("自訂命令"))
        self.ui.Analyze_EXE_hash_Button.setText(self.text_Translate("分析檔案哈希"))
        self.ui.Analyze_EXE_Bit_Button.setText(self.text_Translate("分析檔案位元"))
        self.ui.Analyze_EXE_Funtion_Button.setText(self.text_Translate("分析檔案函數"))
        self.ui.More_Tools_Back.setText(self.text_Translate("返回"))
        self.ui.Look_for_File_Button.setText(self.text_Translate("搜尋本機檔案"))
        self.ui.Encryption_Text_Button.setText(self.text_Translate("加密解密文字"))
        self.ui.Change_Users_Password_Button.setText(self.text_Translate("變更用戶密碼"))
        self.ui.Internet_location_Query_Button.setText(self.text_Translate("網路位置查詢"))
        self.ui.Rework_Network_Configuration_Button.setText(self.text_Translate("重置網路配置"))
        self.ui.Process_Tools_Back.setText(self.text_Translate("返回"))
        self.ui.Process_Total_title.setText(self.text_Translate("進程總數:"))
        self.ui.System_Info_Back.setText(self.text_Translate("返回"))
        self.ui.Customize_CMD_Command_Back.setText(self.text_Translate("返回"))
        self.ui.Customize_CMD_Command_Run_Button.setText(self.text_Translate("執行"))
        self.ui.Customize_CMD_Command_output_title.setText(self.text_Translate("輸出:"))
        self.ui.Analyze_EXE_Back.setText(self.text_Translate("返回"))
        self.ui.Look_for_File_Back.setText(self.text_Translate("返回"))
        self.ui.Look_for_File_Run_Button.setText(self.text_Translate("搜尋"))
        self.ui.Encryption_Text_Back.setText(self.text_Translate("返回"))
        self.ui.Encryption_Text_Run_Button.setText(self.text_Translate("加密"))
        self.ui.Encryption_Text_title2.setText(self.text_Translate("加密 & 解密後"))
        self.ui.Encryption_Text_Password_title.setText(self.text_Translate("密碼:"))
        self.ui.Encryption_Text_title.setText(self.text_Translate("加密 & 解密前"))
        self.ui.Decrypt_Text_Run_Button.setText(self.text_Translate("解密"))
        self.ui.About_Back.setText(self.text_Translate("返回"))
        self.ui.PYAS_Version.setText(self.text_Translate(f"PYAS V{pyas_version}"))
        self.ui.GUI_Made_title.setText(self.text_Translate("介面製作:"))
        self.ui.GUI_Made_Name.setText(self.text_Translate("87owo"))
        self.ui.Core_Made_title.setText(self.text_Translate("核心製作:"))
        self.ui.Core_Made_Name.setText(self.text_Translate("87owo"))
        self.ui.Testers_title.setText(self.text_Translate("測試人員:"))
        self.ui.Testers_Name.setText(self.text_Translate("87owo"))
        self.ui.PYAS_URL_title.setText(self.text_Translate("官方網站:"))
        self.ui.PYAS_URL.setText(self.text_Translate("<html><head/><body><p><a href=\"https://github.com/87owo/PYAS\"><span style=\" text-decoration: underline; color:#000000;\">https://github.com/87owo/PYAS</span></a></p></body></html>"))
        self.ui.Change_Users_Password_Back.setText(self.text_Translate("返回"))
        self.ui.Change_Users_Password_New_Password_title.setText(self.text_Translate("新密碼:"))
        self.ui.Change_Users_Password_User_Name_title.setText(self.text_Translate("用戶名:"))
        self.ui.Change_Users_Password_Run_Button.setText(self.text_Translate("修改"))
        self.ui.Customize_REG_Command_Back.setText(self.text_Translate("返回"))
        self.ui.Value_Path_title.setText(self.text_Translate("值路徑:"))
        self.ui.Value_Name_title.setText(self.text_Translate("值名稱:"))
        self.ui.Value_Type_title.setText(self.text_Translate("值類型:"))
        self.ui.Value_Data_title.setText(self.text_Translate("值資料:"))
        self.ui.Customize_REG_Command_Run_Button.setText(self.text_Translate("確定"))
        self.ui.Value_HEKY_title.setText(self.text_Translate("值HEKY:"))
        self.ui.high_sensitivity_title.setText(self.text_Translate("高靈敏度模式"))
        self.ui.high_sensitivity_illustrate.setText(self.text_Translate("啟用此選項可以提高引擎的靈敏度"))
        self.ui.high_sensitivity_switch_Button.setText(self.text_Translate(self.ui.high_sensitivity_switch_Button.text()))
        self.ui.cloud_services_title.setText(self.text_Translate("雲端掃描服務"))
        self.ui.cloud_services_illustrate.setText(self.text_Translate("啟用此選項可以連接雲端掃描服務"))
        self.ui.cloud_services_switch_Button.setText(self.text_Translate(self.ui.cloud_services_switch_Button.text()))
        self.ui.Setting_Back.setText(self.text_Translate("返回"))
        self.ui.Language_title.setText(self.text_Translate("語言"))
        self.ui.Language_illustrate.setText(self.text_Translate("請選擇語言"))
        self.ui.License_terms_title.setText(self.text_Translate("許可條款:"))
        self.ui.Theme_title.setText(self.text_Translate("顯色主題"))
        self.ui.Theme_illustrate.setText(self.text_Translate("請選擇主題"))
        self.ui.Theme_White.setText(self.text_Translate("白色主題"))
        self.ui.Theme_Black.setText(self.text_Translate("黑色主題"))
        self.ui.Theme_Yellow.setText(self.text_Translate("黃色主題"))
        self.ui.Theme_Red.setText(self.text_Translate("紅色主題"))
        self.ui.Theme_Green.setText(self.text_Translate("綠色主題"))
        self.ui.Theme_Blue.setText(self.text_Translate("藍色主題"))

###################################### 視窗動畫 #####################################

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
        self.opacity.i = 1
        def timeout():
            self.opacity.setOpacity(self.opacity.i/100)
            widget.setGraphicsEffect(self.opacity)
            self.opacity.i += 1
            if self.opacity.i > 100:
                self.timer.stop()
                self.timer.deleteLater()
        self.timer = QTimer()
        self.timer.setInterval(0)
        self.timer.timeout.connect(timeout)
        self.timer.start()

###################################### 切換視窗 #####################################

    def Change_to_State_widget(self):
        if self.ui.State_widget.isHidden():
            self.Change_animation_2(25,50)
            self.Change_animation_3(self.ui.State_widget,0.5)
            self.Change_animation(self.ui.State_widget)
            self.ui.State_widget.show()
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
            self.Change_animation_2(25,168)
            self.Change_animation_3(self.ui.Virus_Scan_widget,0.5)
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
            self.Change_animation_2(25,285)
            self.Change_animation_3(self.ui.Tools_widget,0.5)
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

    def Change_to_Protection_widget(self):
        if self.ui.Protection_widget.isHidden():
            self.Change_animation_2(25,405)
            self.Change_animation_3(self.ui.Protection_widget,0.5)
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

##################################### 主題顏色 #####################################
    
    def Change_Theme(self):
        if self.ui.Theme_Red.isChecked():
            self.ui.Window_widget.setStyleSheet("""QWidget#Window_widget {background-color:rgba(255,150,150,255);}""")
            self.ui.Navigation_Bar.setStyleSheet("""QWidget#Navigation_Bar {background-color:rgba(255,140,140,255);}""")
        elif self.ui.Theme_White.isChecked():
            self.ui.Window_widget.setStyleSheet("""QWidget#Window_widget {background-color:rgba(255,255,255,240);}""")
            self.ui.Navigation_Bar.setStyleSheet("""QWidget#Navigation_Bar {background-color:rgba(240,240,240,255);}""")
        elif self.ui.Theme_Black.isChecked():
            self.ui.Window_widget.setStyleSheet("""QWidget#Window_widget {background-color:rgba(150,150,150,255);}""")
            self.ui.Navigation_Bar.setStyleSheet("""QWidget#Navigation_Bar {background-color:rgba(140,140,140,255);}""")
        elif self.ui.Theme_Green.isChecked():
            self.ui.Window_widget.setStyleSheet("""QWidget#Window_widget {background-color:rgba(150,255,150,255);}""")
            self.ui.Navigation_Bar.setStyleSheet("""QWidget#Navigation_Bar {background-color:rgba(130,255,130,255);}""")
        elif self.ui.Theme_Yellow.isChecked():
            self.ui.Window_widget.setStyleSheet("""QWidget#Window_widget {background-color:rgba(255,255,150,255);}""")
            self.ui.Navigation_Bar.setStyleSheet("""QWidget#Navigation_Bar {background-color:rgba(240,240,140,255);}""")
        elif self.ui.Theme_Blue.isChecked():
            self.ui.Window_widget.setStyleSheet("""QWidget#Window_widget {background-color:rgba(0,200,255,255);}""")
            self.ui.Navigation_Bar.setStyleSheet("""QWidget#Navigation_Bar {background-color:rgba(0,190,255,255);}""")

##################################### 操作事件 #####################################

    def mousePressEvent(self, event):
        x = event.x()
        y = event.y()
        if event.button()==Qt.LeftButton and x >= 10 and x <= 841 and y >= 10 and y <= 49:
            self.m_flag=True
            self.m_Position=event.globalPos()-self.pos() #獲取鼠標相對窗口的位置
            event.accept()
            while self.pyas_opacity > 60 and self.m_flag == True:
                time.sleep(0.002)
                self.pyas_opacity -= 1
                self.setWindowOpacity(self.pyas_opacity/100)
                QApplication.processEvents()
        
    def mouseMoveEvent(self, QMouseEvent):
        try:
            if Qt.LeftButton and self.m_flag:
                self.move(QMouseEvent.globalPos()-self.m_Position)#更改窗口位置
                QApplication.processEvents()
                QMouseEvent.accept()
        except:
            pass
        
    def mouseReleaseEvent(self, QMouseEvent):
        self.m_flag=False
        self.setCursor(QCursor(Qt.ArrowCursor))
        while self.pyas_opacity < 100 and self.m_flag == False:
            time.sleep(0.002)
            self.pyas_opacity += 1
            self.setWindowOpacity(self.pyas_opacity/100)
            QApplication.processEvents()

    def paintEvent(self, event):# 圓角
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

    def onTrayIconActivated(self, reason):
        if reason == QSystemTrayIcon.Trigger or reason == QSystemTrayIcon.DoubleClick:
            self.showNormal()
            while self.pyas_opacity < 100:
                time.sleep(0.001)
                self.pyas_opacity += 1
                self.setWindowOpacity(self.pyas_opacity/100)
                QApplication.processEvents()

    def show_pyas_ui(self):
        self.show()
        while self.pyas_opacity < 100:
            time.sleep(0.001)
            self.pyas_opacity += 1
            self.setWindowOpacity(self.pyas_opacity/100)
            QApplication.processEvents()

    def closeEvent(self, event):
        question = QMessageBox.warning(self,self.text_Translate("警告"),self.text_Translate("您確定要退出 PYAS 和相關防護嗎?"),QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)
        if question == 16384:
            self.proc_protect = False
            self.file_protect = False
            self.mbr_protect = False
            self.reg_protect = False
            while self.pyas_opacity > 0:
                time.sleep(0.001)
                self.pyas_opacity -= 1
                self.setWindowOpacity(self.pyas_opacity/100)
                QApplication.processEvents()
            self.tray_icon.hide()
            self.hide()
            app.quit()
        else:
            event.ignore()

###################################### 錯誤回報 #####################################

    def pyas_bug_log(self, e):
        try:
            print(f"[Error] {e}")
            QMessageBox.critical(self,self.text_Translate("錯誤"),self.text_Translate(f"錯誤: {e}"),QMessageBox.Ok)
        except:
            pass

##################################### 通知顯示 #####################################

    def system_notification(self,text):
        try:
            now_time = time.strftime('%Y/%m/%d %H:%M:%S')
            self.ui.State_output.append(f"[{now_time}] {text}")
            self.tray_icon.showMessage(now_time, text, 5)
        except:
            pass

###################################### 密鑰認證 #####################################

    def pyas_key(self):
        try:
            with open(str(sys.argv[0]), "rb") as f:
                file_md5 = str(md5(f.read()).hexdigest())
            response = requests.get("http://27.147.30.238:5001/pyas", params={"key": file_md5}, timeout=3)
            return response.status_code == 200 and response.text == "True"
        except:
            return False

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

    def high_sensitivity_switch(self):
        sw_state = self.ui.high_sensitivity_switch_Button.text()
        if sw_state == self.text_Translate("已關閉"):
            self.high_sensitivity = 1
            self.pyasConfig["high_sensitivity"] = 1
            self.writeConfig(self.pyasConfig)
            self.ui.high_sensitivity_switch_Button.setText(self.text_Translate("已開啟"))
            self.ui.high_sensitivity_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")
        elif sw_state == self.text_Translate("已開啟"):
            self.high_sensitivity = 0
            self.pyasConfig["high_sensitivity"] = 0
            self.writeConfig(self.pyasConfig)
            self.ui.high_sensitivity_switch_Button.setText(self.text_Translate("已關閉"))
            self.ui.high_sensitivity_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,20,20,30);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,20,20,50);}""")

    def cloud_services_switch(self):
        sw_state = self.ui.cloud_services_switch_Button.text()
        if sw_state == self.text_Translate("已關閉"):
            self.cloud_services = 1
            self.pyasConfig["cloud_services"] = 1
            self.writeConfig(self.pyasConfig)
            self.ui.cloud_services_switch_Button.setText(self.text_Translate("已開啟"))
            self.ui.cloud_services_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")
        elif sw_state == self.text_Translate("已開啟"):
            self.cloud_services = 0
            self.pyasConfig["cloud_services"] = 0
            self.writeConfig(self.pyasConfig)
            self.ui.cloud_services_switch_Button.setText(self.text_Translate("已關閉"))
            self.ui.cloud_services_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,20,20,30);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,20,20,50);}""")

##################################### 病毒掃描 #####################################

    def Virus_Scan_Break(self):
        self.Virus_Scan = False

    def Virus_Solve(self):
        try:
            for line in self.Virus_List:
                try:
                    if ":/Windows" not in str(line):
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
            self.ui.State_icon.setPixmap(QtGui.QPixmap(":/icon/Icon/check.png"))
            self.ui.State_title.setText(self.text_Translate("此裝置已受到防護"))
            self.Safe = True
        except Exception as e:
            self.pyas_bug_log(e)

    def api_scan(self, types, file):
        try:
            if self.cloud_services == 1:
                with open(file, "rb") as f:
                    text = str(md5(f.read()).hexdigest())
                strBody = f'-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="md5s"\r\n\r\n{text}\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="format"\r\n\r\nXML\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="product"\r\n\r\n360zip\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="combo"\r\n\r\n360zip_main\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="v"\r\n\r\n2\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="osver"\r\n\r\n5.1\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="vk"\r\n\r\na03bc211\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="mid"\r\n\r\n8a40d9eff408a78fe9ec10a0e7e60f62\r\n-------------------------------7d83e2d7a141e--'
                response = requests.post('http://qup.f.360.cn/file_health_info.php', data=strBody, timeout=3)
                return response.status_code == 200 and float(ET.fromstring(response.text).find('.//e_level').text) > 50
        except:
            return False

    def sign_scan(self, file):
        try:
            if self.high_sensitivity == 0:
                pe = PE(file, fast_load=True)
                pe.close()
                return pe.OPTIONAL_HEADER.DATA_DIRECTORY[DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].VirtualAddress == 0
            return True
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
                if (sum(1 for num in fn if num in vfl)/len(vfl)) - (sum(1 for num in fn if num not in vfl)/len(vfl)) == 1.0:
                    return True
            return False
        except:
            return False

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
            self.ui.State_icon.setPixmap(QtGui.QPixmap(":/icon/Icon/X2.png"))
            self.ui.State_title.setText(self.text_Translate("此裝置當前不安全"))
            self.ui.Virus_Scan_Solve_Button.show()
            self.ui.Virus_Scan_choose_Button.show()
            self.ui.Virus_Scan_Break_Button.hide()
            self.Virus_Scan = False
            self.Safe = False
            text = self.text_Translate(f"當前發現 {len(self.Virus_List)} 個病毒")
        else:
            self.ui.Virus_Scan_Break_Button.hide()
            self.ui.Virus_Scan_choose_Button.show()
            self.Virus_Scan = False
            self.Safe = True
            text = self.text_Translate("當前未發現病毒")
        self.ui.Virus_Scan_text.setText(text)
        self.system_notification(text)

    def Virus_Scan_Choose_Menu(self):
        if self.ui.Virus_Scan_choose_widget.isHidden():
            self.ui.Virus_Scan_choose_widget.show()
            self.Change_animation_4(self.ui.Virus_Scan_choose_widget,100,0,101)
        else:
            self.ui.Virus_Scan_choose_widget.hide()

##################################### 檔案掃描 #####################################
    
    def file_scan(self):
        self.Virus_List = []
        self.ui.Virus_Scan_choose_widget.hide()
        self.ui.Virus_Scan_Solve_Button.hide()
        self.ui.Virus_Scan_ProgressBar.hide()
        self.Virus_List_output=QStringListModel()
        self.Virus_List_output.setStringList(self.Virus_List)
        self.ui.Virus_Scan_output.setModel(self.Virus_List_output)
        file, filetype= QFileDialog.getOpenFileName(self,self.text_Translate("病毒掃描"),"C:/","")
        try:
            if file != "":
                self.Virus_Scan = True
                self.ui.Virus_Scan_text.setText(self.text_Translate("正在初始化中..."))
                self.ui.Virus_Scan_choose_Button.hide()
                QApplication.processEvents()
                if self.sign_scan(file):
                    if self.api_scan("md5", file) or self.pe_scan(file):
                        self.write_scan(file)
                self.answer_scan()
            else:
                self.ui.Virus_Scan_text.setText(self.text_Translate("請選擇掃描方式"))
        except Exception as e:
            self.pyas_bug_log(e)
            self.ui.Virus_Scan_text.setText(self.text_Translate("請選擇掃描方式"))
            self.ui.Virus_Scan_choose_Button.show()
            self.ui.Virus_Scan_Break_Button.hide()

##################################### 路徑掃描 #####################################
    
    def path_scan(self):
        self.ui.Virus_Scan_choose_widget.hide()
        self.ui.Virus_Scan_Solve_Button.hide()
        self.ui.Virus_Scan_ProgressBar.hide()
        self.Virus_List = []
        self.Virus_List_output=QStringListModel()
        self.Virus_List_output.setStringList(self.Virus_List)
        self.ui.Virus_Scan_output.setModel(self.Virus_List_output)
        path = QFileDialog.getExistingDirectory(self,self.text_Translate("病毒掃描"),"C:/")
        try:
            if path != "":
                self.Virus_Scan = True
                self.ui.Virus_Scan_text.setText(self.text_Translate("正在初始化中"))
                self.ui.Virus_Scan_choose_Button.hide()
                self.ui.Virus_Scan_Break_Button.show()
                QApplication.processEvents()
                self.traverse_path(path,"")
                self.answer_scan()
            else:
                self.ui.Virus_Scan_text.setText(self.text_Translate("請選擇掃描方式"))
        except Exception as e:
            self.pyas_bug_log(e)
            self.ui.Virus_Scan_text.setText(self.text_Translate("請選擇掃描方式"))
            self.ui.Virus_Scan_choose_Button.show()
            self.ui.Virus_Scan_Break_Button.hide()

##################################### 全盤掃描 #####################################
    
    def disk_scan(self):
        try:
            self.ui.Virus_Scan_choose_widget.hide()
            self.ui.Virus_Scan_text.setText(self.text_Translate("正在初始化中"))
            QApplication.processEvents()
            self.Virus_Scan = True
            self.ui.Virus_Scan_Solve_Button.hide()
            self.ui.Virus_Scan_ProgressBar.hide()
            self.ui.Virus_Scan_choose_Button.hide()
            self.ui.Virus_Scan_Break_Button.show()
            self.Virus_List = []
            self.Virus_List_output=QStringListModel()
            self.Virus_List_output.setStringList(self.Virus_List)
            self.ui.Virus_Scan_output.setModel(self.Virus_List_output)
            for d in range(26):
                try:
                    self.traverse_path(str(chr(65+d))+":/","")
                except:
                    pass
            self.answer_scan()
        except Exception as e:
            self.pyas_bug_log(e)
            self.ui.Virus_Scan_text.setText(self.text_Translate("請選擇掃描方式"))
            self.ui.Virus_Scan_choose_Button.show()
            self.ui.Virus_Scan_Break_Button.hide()

    def traverse_path(self,path,rfp):
        sflist = [".exe",".dll",".com",".msi",".js",".vbs",".xls",".xlsx",".doc",".docx"]
        for fd in os.listdir(path):
            try:
                fullpath = str(os.path.join(path,fd)).replace("\\", "/")
                if self.Virus_Scan == False:
                    self.ui.Virus_Scan_Break_Button.hide()
                    break
                elif ":/Windows" in fullpath or ":/$Recycle.Bin" in fullpath or "AppData" in fullpath:#路徑過濾
                    continue
                elif os.path.isdir(fullpath):
                    self.traverse_path(fullpath,rfp)
                else:
                    self.ui.Virus_Scan_text.setText(self.text_Translate(f"正在掃描: ")+fullpath)
                    QApplication.processEvents()
                    if self.sign_scan(fullpath):
                        if self.high_sensitivity == 1:
                            if self.api_scan("md5", fullpath) or self.pe_scan(fullpath):
                                self.write_scan(fullpath)
                        elif str(os.path.splitext(fd)[1]).lower() in sflist:
                            if self.api_scan("md5", fullpath) or self.pe_scan(fullpath):
                                self.write_scan(fullpath)
            except:
                continue

##################################### 實用工具 #####################################

    def Repair_System_Files(self):
        try:
            question = QMessageBox.warning(self,self.text_Translate("修復系統檔案"),self.text_Translate("您確定要修復系統檔案嗎?"),QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)
            if question == 16384:
                subprocess.run("sfc /scannow", check=True)
        except Exception as e:
            self.pyas_bug_log(e)

    def Clean_System_Files(self):
        try:
            question = QMessageBox.warning(self,self.text_Translate("清理系統檔案"),self.text_Translate("您確定要清理系統檔案嗎?"),QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)
            if question == 16384:
                subprocess.run("cleanmgr", check=True)
        except Exception as e:
            self.pyas_bug_log(e)

    def Enable_Safe_Mode(self):
        try:
            question = QMessageBox.warning(self,self.text_Translate("啟用安全模式"),self.text_Translate("您確定要啟用安全模式嗎?"),QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)
            if question == 16384:
                subprocess.run("bcdedit /set {default} safeboot minimal", check=True)
                question = QMessageBox.warning(self,"reboot",self.text_Translate("使用此選項需要重啟，您確定要重啟嗎?"),QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)
                if question == 16384:
                    subprocess.run("shutdown -r -t 0", check=True)
        except Exception as e:
            self.pyas_bug_log(e) 

    def Disable_Safe_Mode(self):
        try:
            question = QMessageBox.warning(self,self.text_Translate("禁用安全模式"),self.text_Translate("您確定要禁用安全模式嗎?"),QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)
            if question == 16384:
                subprocess.run("bcdedit /deletevalue {current} safeboot", check=True)
                question = QMessageBox.warning(self,"reboot",self.text_Translate("使用此選項需要重啟，您確定要重啟嗎?"),QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)
                if question == 16384:
                    subprocess.run("shutdown -r -t 0", check=True)
        except Exception as e:
            self.pyas_bug_log(e)

    def System_Info_update(self):
        try:
            version = sys.getwindowsversion()
            self.ui.System_Info_View.setText(f"CPU Core: {os.cpu_count()}\nSYS Info: {sys.platform}\nSYS Vers: {version.major}.{version.minor} build {version.build}\nSYS Name: {os.getlogin()}")
        except Exception as e:
            self.pyas_bug_log(e)

    def Delete_Private_File(self):
        file, filetype = QFileDialog.getOpenFileName(self,self.text_Translate("刪除檔案"),"C:/","")
        if file != "" and file != str(sys.argv[0]):
            question = QMessageBox.warning(self,self.text_Translate("刪除檔案"),self.text_Translate("您確定要刪除此檔案嗎?"),QMessageBox.Yes|QMessageBox.No,QMessageBox.Yes)
            if question == 16384:
                try:
                    os.remove(file)
                    QMessageBox.information(self,self.text_Translate("刪除成功"),self.text_Translate("成功: 刪除成功"),QMessageBox.Ok)
                except Exception as e:
                    self.pyas_bug_log(e)
     
    def Customize_CMD_Command(self):
        CMD_Command = self.ui.Customize_CMD_Command_lineEdit.text()
        if CMD_Command != "":
            try:
                self.ui.Customize_CMD_Command_output.setText(str(subprocess.run(CMD_Command, capture_output=True, text=True).stdout))
                QMessageBox.information(self,self.text_Translate("完成"),self.text_Translate("成功: 執行成功"),QMessageBox.Ok,QMessageBox.Ok)
            except Exception as e:
                QMessageBox.critical(self,self.text_Translate("錯誤"),self.text_Translate(f'錯誤: "{CMD_Command}" 不是有效命令'),QMessageBox.Ok,QMessageBox.Ok)

    def Customize_REG_Command(self):
        continue_v = True
        Value_name = str(self.ui.Value_Name_input.text())
        Value_Path = str(self.ui.Value_Path_input.text())
        Value_Data = str(self.ui.Value_Data_input.text())
        Value_Type = str(self.ui.Value_Type_input.text())
        Value_HEKY = str(self.ui.Value_HEKY_input.text())
        heky_dict = {"HKEY_CLASSES_ROOT": win32con.HKEY_CLASSES_ROOT,"HKEY_CURRENT_USER": win32con.HKEY_CURRENT_USER,"HKEY_LOCAL_MACHINE": win32con.HKEY_LOCAL_MACHINE,"HKEY_USERS": win32con.HKEY_USERS,"HKEY_CURRENT_CONFIG": win32con.HKEY_CURRENT_CONFIG}
        if Value_HEKY in heky_dict:
            Value_HEKY = heky_dict[Value_HEKY]
        else:
            QMessageBox.critical(self, self.text_Translate("錯誤"), self.text_Translate("錯誤: 您輸入了錯誤的HEKY"), QMessageBox.Ok)
            continue_v = False
        value_types_dict = {"REG_BINARY": win32con.REG_BINARY,"REG_DWORD": win32con.REG_DWORD,"REG_DWORD_LITTLE_ENDIAN": win32con.REG_DWORD_LITTLE_ENDIAN,"REG_DWORD_BIG_ENDIAN": win32con.REG_DWORD_BIG_ENDIAN,"REG_EXPAND_SZ": win32con.REG_EXPAND_SZ,"REG_LINK": win32con.REG_LINK,"REG_MULTI_SZ": win32con.REG_MULTI_SZ,"REG_NONE": win32con.REG_NONE,"REG_QWORD": win32con.REG_QWORD,"REG_QWORD_LITTLE_ENDIAN": win32con.REG_QWORD_LITTLE_ENDIAN,"REG_SZ": win32con.REG_SZ}  
        if Value_Type in value_types_dict:
            Value_Type = value_types_dict[Value_Type]
        else:
            QMessageBox.critical(self, self.text_Translate("錯誤"), self.text_Translate("錯誤: 您輸入了錯誤的TYPE"), QMessageBox.Ok)
            continue_v = False
        if continue_v:
            if QMessageBox.warning(self,self.text_Translate("警告"),self.text_Translate("您確定要新增值或是修改值嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
                try:
                    key = win32api.RegOpenKey(Value_HEKY,Value_Path,0,win32con.KEY_ALL_ACCESS)
                    win32api.RegSetValueEx(key, Value_name,0,Value_Type,Value_Data)
                    win32api.RegCloseKey(key)
                    QMessageBox.information(self,self.text_Translate("成功"),self.text_Translate("成功: 成功的創建或修改註冊表值"),QMessageBox.Ok)
                except Exception as e:
                    self.pyas_bug_log(e)

    def Analyze_EXE(self,button):
        if button == self.ui.Analyze_EXE_Funtion_Button:
            file, filetype= QFileDialog.getOpenFileName(self,self.text_Translate("分析檔案函數"),"C:/","EXE OR DLL File *.exe *.dll")
            if file != "":
                try:
                    pe = PE(file)
                    pe.close()
                    self.ui.Analyze_EXE_Output.setText("")
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for func in entry.imports:
                            self.ui.Analyze_EXE_Output.append(str(func.name, "utf-8"))
                    self.Change_Tools(self.ui.Analyze_EXE_widget)
                    QApplication.processEvents()
                except:
                    pass
        elif button == self.ui.Analyze_EXE_hash_Button:
            file, filetype= QFileDialog.getOpenFileName(self,self.text_Translate("分析檔案哈希值"),"C:/","All File *.*")
            if file != "":
                try:
                    with open(file,"rb") as f:
                        bytes = f.read()
                    readable_hash = str(md5(bytes).hexdigest())
                    readable_hash2 = str(sha1(bytes).hexdigest())
                    readable_hash3 = str(sha256(bytes).hexdigest())
                    self.ui.Analyze_EXE_Output.setText("")
                    self.ui.Analyze_EXE_Output.append(f"MD5: {readable_hash}\nSHA1: {readable_hash2}\nSHA256: {readable_hash3}")
                    self.Change_Tools(self.ui.Analyze_EXE_widget)
                    QApplication.processEvents()
                except:
                    pass
        else:
            file, filetype= QFileDialog.getOpenFileName(self,self.text_Translate("分析檔案位元"),"C:/","EXE OR DLL File *.exe *.dll")
            if file != "":
                try:
                    pe = PE(file,fast_load=True)
                    pe.close()
                    self.ui.Analyze_EXE_Output.setText("")
                    for section in pe.sections:
                        self.ui.Analyze_EXE_Output.append(f"{section.Name.decode()} {hex(section.VirtualAddress)} {hex(section.Misc_VirtualSize)} {section.Characteristics}")
                    self.Change_Tools(self.ui.Analyze_EXE_widget)
                    QApplication.processEvents()
                except:
                    pass

    def find_file_input(self):
        try:
            file_name = self.ui.Look_for_File_input.text()
            if file_name != "":
                self.find_files = []
                for d in range(26):
                    try:
                        self.traverse_find_file(str(chr(65+d))+":/",file_name)
                    except:
                        pass
                if self.find_files != []:
                    self.ui.Look_for_File_output.setText("")
                    for find_file in self.find_files:
                        self.ui.Look_for_File_output.append(find_file)
                    QApplication.processEvents()
                    self.Change_Tools(self.ui.Look_for_File_widget)
                else:
                    QMessageBox.critical(self,self.text_Translate("錯誤"),self.text_Translate("錯誤: 未找到檔案"),QMessageBox.Ok)
        except Exception as e:
            self.pyas_bug_log(e)

    def traverse_find_file(self,path,ffile):
        for fd in os.listdir(path):
            try:
                fullpath = str(os.path.join(path,fd)).replace("\\", "/")
                if ":/Windows" in fullpath or ":/$Recycle.Bin" in fullpath or ":/ProgramData" in fullpath or "PerfLogs" in fullpath:
                    continue
                elif os.path.isdir(fullpath):
                    self.ui.Look_for_File_output.setText(self.text_Translate("正在尋找: ")+fullpath)
                    QApplication.processEvents()
                    self.traverse_find_file(fullpath,ffile)
                elif ffile in str(fd):
                    self.find_files.append(str(self.text_Translate("找到檔案: ")+f"{fullpath}\n"+self.text_Translate("創建日期: ")+f"{time.ctime(os.path.getmtime(fullpath))}\n"))
            except:
                continue

    def Encryption_Text(self):
        try:
            self.encrypt_zh(self.ui.Encryption_Text_input.toPlainText(),self.ui.Encryption_Text_Password_input.text())
        except Exception as e:
            self.pyas_bug_log(e)

    def Decrypt_Text(self):
        try:
            self.decrypt_zh(self.ui.Encryption_Text_input.toPlainText(),self.ui.Encryption_Text_Password_input.text())
        except Exception as e:
            self.pyas_bug_log(e)

    def encrypt_zh(self,e,e2):
        try:
            self.ui.Encryption_Text_output.setText(str(cryptocode.encrypt(e,e2)))
        except Exception as e:
            self.pyas_bug_log(e)

    def decrypt_zh(self,e,e2):
        try:
            self.ui.Encryption_Text_output.setText(str(cryptocode.decrypt(e,e2)))
        except Exception as e:
            self.pyas_bug_log(e)

    def Change_Users_Password(self):
        try:
            username = self.ui.Change_Users_Password_User_Name_input.text()
            password = self.ui.Change_Users_Password_New_Password_input.text()
            if QMessageBox.warning(self,self.text_Translate("警告"),self.text_Translate("您確定要修改用戶密碼嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
                if password == "":
                    subprocess.run("net user {} {}".format(username,'""'))
                else:
                    subprocess.run("net user {} {}".format(username,password))
        except Exception as e:
            self.pyas_bug_log(e)

    def Internet_location_Query(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            QMessageBox.information(self,self.text_Translate("位置查詢"),self.text_Translate(f"您的IP 配置是:{s.getsockname()[0]}"),QMessageBox.Ok)
            s.close()
        except Exception as e:
            self.pyas_bug_log(e)

    def reset_network(self):
        try:
            if QMessageBox.warning(self,self.text_Translate("警告"),self.text_Translate("您確定要重置配置嗎?"),QMessageBox.Yes|QMessageBox.No) == 16384:
                subprocess.run("netsh winsock reset", shell=True)
                QMessageBox.information(self,self.text_Translate("完成"),self.text_Translate("網路配置重置成功"),QMessageBox.Ok)
        except Exception as e:
            self.pyas_bug_log(e)

    def Setting_Back(self):
        self.ui.Navigation_Bar.show()
        self.ui.Setting_widget.hide()

    def Process_list(self):
        try:
            self.Process_list_app = []
            self.Process_list_app_exe = []
            self.Process_list_app_pid = []
            self.Process_list_app_name = []
            self.Process_list_app_user = []
            for p in psutil.process_iter():
                try:
                    self.Process_list_app.append(f"{p.name()} ({p.pid}) > {p.exe()}")
                    self.Process_list_app_pid.append(p.pid)
                    self.Process_list_app_exe.append(p.exe())
                    self.Process_list_app_name.append(p.name())
                    self.Process_list_app_user.append(p.username())
                    QApplication.processEvents()
                except:
                    pass
            if len(self.Process_list_app_name) != self.Process_quantity:
                self.Process_quantity = len(self.Process_list_app_name)
                self.ui.Process_Total_View.setText(str(self.Process_quantity))
                self.Process_sim.setStringList(self.Process_list_app)
                self.ui.Process_list.setModel(self.Process_sim)
        except Exception as e:
            self.pyas_bug_log(e)

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
        except:
            pass

##################################### 防護開關 #####################################

    def protect_threading_init(self):
        if self.ui.Protection_switch_Button.text() == self.text_Translate("已開啟"):
            self.proc_protect = False
            self.ui.Protection_switch_Button.setText(self.text_Translate("已關閉"))
            self.ui.Protection_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,20,20,30);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,20,20,50);}""")
            self.system_notification(self.text_Translate("進程防護已關閉"))
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
            self.system_notification(self.text_Translate("檔案防護已關閉"))
        else:
            self.file_protect = True
            self.ui.Protection_switch_Button_2.setText(self.text_Translate("已開啟"))
            self.ui.Protection_switch_Button_2.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")
            for d in range(26):
                if os.path.exists(str(chr(65+d)+":\\")):
                    Thread(target=self.protect_system_file, args=(str(chr(65+d)+":\\"),)).start()

    def protect_threading_init_3(self):
        if self.ui.Protection_switch_Button_3.text() == self.text_Translate("已開啟"):
            self.mbr_protect = False
            self.ui.Protection_switch_Button_3.setText(self.text_Translate("已關閉"))
            self.ui.Protection_switch_Button_3.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,20,20,30);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,20,20,50);}""")
            self.system_notification(self.text_Translate("引導分區防護已關閉"))
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
            self.system_notification(self.text_Translate("註冊表防護已關閉"))
        else:
            self.reg_protect = True
            self.ui.Protection_switch_Button_4.setText(self.text_Translate("已開啟"))
            self.ui.Protection_switch_Button_4.setStyleSheet("""
            QPushButton{border:none;background-color:rgba(20,200,20,100);border-radius: 15px;}
            QPushButton:hover{background-color:rgba(20,200,20,120);}""")
            Thread(target=self.protect_system_reg_repair).start()

##################################### 實時防護 #####################################

    def protect_system_processes(self):
        while self.proc_protect:
            for p in psutil.process_iter():
                try:
                    time.sleep(0.001)
                    file, name = str(p.exe()), str(p.name())
                    if str(sys.argv[0]) == file or ":\Windows" in file or ":\Program" in file or ":\XboxGames" in file or "AppData" in file:
                        continue
                    elif self.high_sensitivity == 0:
                        if self.api_scan('md5', file) or self.pe_scan(file):
                            p.kill()
                            self.system_notification(self.text_Translate("成功攔截病毒: ")+name)
                    elif self.high_sensitivity == 1:
                        if self.sign_scan(file) or self.api_scan('md5', file) or self.pe_scan(file):
                            p.kill()
                            self.system_notification(self.text_Translate("成功攔截病毒: ")+name)
                except:
                    pass

    def protect_system_file(self,path):
        sflist = [".exe",".dll",".com",".msi",".js",".vbs",".xls",".xlsx",".doc",".docx"]
        hDir = win32file.CreateFile(path,win32con.GENERIC_READ,win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,None,win32con.OPEN_EXISTING,win32con.FILE_FLAG_BACKUP_SEMANTICS,None)
        while self.file_protect:
            try:
                for action, file in win32file.ReadDirectoryChangesW(hDir,1024,True,win32con.FILE_NOTIFY_CHANGE_FILE_NAME | win32con.FILE_NOTIFY_CHANGE_DIR_NAME | win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES | win32con.FILE_NOTIFY_CHANGE_SIZE | win32con.FILE_NOTIFY_CHANGE_LAST_WRITE | win32con.FILE_NOTIFY_CHANGE_SECURITY,None,None):
                    file = str(path+file)
                    if str(sys.argv[0]) == file or ":\$Recycle" in file or ":\Windows" in file or ":\Program" in file or ":\XboxGames" in file or "AppData" in file:
                        continue
                    elif action and str(os.path.splitext(file)[1]).lower() in sflist and self.sign_scan(file):
                        if self.api_scan("md5", file):
                            os.remove(file)
                            self.system_notification(self.text_Translate("成功刪除病毒: ")+file)
            except:
                pass

    def protect_system_mbr_repair(self):
        while self.mbr_protect and self.mbr_value != None:
            try:
                time.sleep(0.5)
                with open(r"\\.\PhysicalDrive0", "r+b") as f:
                    if f.read(512) != self.mbr_value:
                        f.seek(0)
                        f.write(self.mbr_value)
                        self.system_notification(self.text_Translate("成功修復引導分區: PhysicalDrive0"))
            except:
                pass

    def protect_system_reg_repair(self):
        while self.reg_protect:
            try:
                Permission = ["NoControlPanel", "NoDrives", "NoControlPanel", "NoFileMenu", "NoFind", "NoRealMode", "NoRecentDocsMenu","NoSetFolders", \
                "NoSetFolderOptions", "NoViewOnDrive", "NoClose", "NoRun", "NoDesktop", "NoLogOff", "NoFolderOptions", "RestrictRun","DisableCMD", \
                "NoViewContexMenu", "HideClock", "NoStartMenuMorePrograms", "NoStartMenuMyGames", "NoStartMenuMyMusic" "NoStartMenuNetworkPlaces", \
                "NoStartMenuPinnedList", "NoActiveDesktop", "NoSetActiveDesktop", "NoActiveDesktopChanges", "NoChangeStartMenu", "ClearRecentDocsOnExit", \
                "NoFavoritesMenu", "NoRecentDocsHistory", "NoSetTaskbar", "NoSMHelp", "NoTrayContextMenu", "NoViewContextMenu", "NoWindowsUpdate", \
                "NoWinKeys", "StartMenuLogOff", "NoSimpleNetlDList", "NoLowDiskSpaceChecks", "DisableLockWorkstation", "NoManageMyComputerVerb",\
                "DisableTaskMgr", "DisableRegistryTools", "DisableChangePassword", "Wallpaper", "NoComponents", "NoAddingComponents", "Restrict_Run"]
                win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",0,win32con.KEY_ALL_ACCESS),"Explorer")#創建鍵
                win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",0,win32con.KEY_ALL_ACCESS),"Explorer")
                win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",0,win32con.KEY_ALL_ACCESS),"System")
                win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",0,win32con.KEY_ALL_ACCESS),"System")
                win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",0,win32con.KEY_ALL_ACCESS),"ActiveDesktop")
                win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,"SOFTWARE\Policies\Microsoft\Windows",0,win32con.KEY_ALL_ACCESS),"System")
                win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,"SOFTWARE\Policies\Microsoft\Windows",0,win32con.KEY_ALL_ACCESS),"System")
                win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,"Software\Policies\Microsoft",0,win32con.KEY_ALL_ACCESS),"MMC")
                win32api.RegCreateKey(win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,"Software\Policies\Microsoft\MMC",0,win32con.KEY_ALL_ACCESS),"{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}")
                keys = [win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",0,win32con.KEY_ALL_ACCESS),\
                win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",0,win32con.KEY_ALL_ACCESS),\
                win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",0,win32con.KEY_ALL_ACCESS),\
                win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",0,win32con.KEY_ALL_ACCESS),\
                win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop",0,win32con.KEY_ALL_ACCESS),\
                win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,"SOFTWARE\Policies\Microsoft\Windows\System",0,win32con.KEY_ALL_ACCESS),\
                win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,"SOFTWARE\Policies\Microsoft\Windows\System",0,win32con.KEY_ALL_ACCESS),\
                win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,"Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}",0,win32con.KEY_ALL_ACCESS)]
                for key in keys:
                    for i in Permission:
                        try:
                            time.sleep(0.001)
                            win32api.RegDeleteValue(key,i)
                        except:
                            pass
                    win32api.RegCloseKey(key)
            except:
                pass

##################################### 初始設定 #####################################

if __name__ == '__main__':
    pyas_version, pyae_version = "2.6.9", "2.3.7"
    QtCore.QCoreApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    QtGui.QGuiApplication.setAttribute(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QtWidgets.QApplication(sys.argv)
    MainWindow_Controller()
    sys.exit(app.exec_())
