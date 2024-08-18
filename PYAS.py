import os, gc, sys, time, json, psutil
import msvcrt, ctypes, pyperclip, win32file
import win32gui, win32api, win32con
from PYAS_Engine import YRScan, DLScan
from PYAS_Suffixes import slist, alist
from PYAS_Language import translate_dict
from PYAS_Interface import Ui_MainWindow
from threading import Thread
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from subprocess import *

class MainWindow_Controller(QMainWindow):
    def __init__(self):
        super(MainWindow_Controller, self).__init__()
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.pyas = sys.argv[0].replace("\\", "/")
        self.dir = os.path.dirname(self.pyas)
        self.pyae_version = "AI Engine"
        self.pyas_version = "3.1.6"
        self.first_startup = True
        self.init_data_base()
        self.init_tray_icon()
        self.init_config_qtui()
        self.init_config_read()
        self.init_config_boot()
        self.init_control()
        self.init_threads()
        self.init_startup()

    def init_threads(self):
        self.protect_proc_init()
        self.protect_file_init()
        self.protect_sys_init()
        self.protect_drv_init()
        self.protect_net_init()
        self.block_window_init()

    def init_tray_icon(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.activated.connect(self.init_show_pyas)
        self.tray_icon.setIcon(QFileIconProvider().icon(QFileInfo(self.pyas)))
        self.tray_icon.show()

    def init_startup(self):
        try:
            if len(sys.argv) > 1: 
                param = sys.argv[1]
                if "h" not in param:
                    self.init_show_pyas()
            elif len(sys.argv) <= 1:
                self.init_show_pyas()
            self.first_startup = False
        except:
            pass

    def init_data_base(self):
        try:
            self.model = DLScan()
            data_path = os.path.join(self.dir, "Model")
            for root, dirs, files in os.walk(data_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    self.model.load_model(file_path)
            self.rules = YRScan()
            data_path = os.path.join(self.dir, "Rules") 
            for root, dirs, files in os.walk(data_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    self.rules.load_rules(file_path)
        except Exception as e:
            self.bug_event(e)

    def init_config_boot(self):
        try:
            with open(r"\\.\PhysicalDrive0", "r+b") as f:
                self.mbr_value = f.read(512)
            if self.mbr_value[510:512] != b'\x55\xAA':
                self.mbr_value = False
        except Exception as e:
            self.mbr_value = False
            self.bug_event(self.trans(f"引導防護錯誤: ")+str(e))

    def write_config(self, config):
        try:
            with open("C:/ProgramData/PYAS/PYAS.json", "w") as f:
                f.write(json.dumps(config, indent=4, ensure_ascii=False))
        except Exception as e:
            self.bug_event(e)

    def init_config_read(self):
        try:
            self.track_proc = None
            self.exist_process = set()
            for p in psutil.process_iter():
                self.exist_process.add(p.pid)
            if not os.path.exists("C:/ProgramData/PYAS"): 
                os.makedirs("C:/ProgramData/PYAS")
            if not os.path.exists("C:/ProgramData/PYAS/PYAS.json"): 
                self.write_config({"language":"en_US","theme_color":"White",
                "high_sensitive":0,"extension_kits":0,"cloud_services":"None"})
            try:
                with open("C:/ProgramData/PYAS/PYAS.json", "r") as f: 
                    self.json = json.load(f)
            except:
                self.json = {"language":"en_US","theme_color":"White",
                "high_sensitive":0,"extension_kits":0,"cloud_services":"None"}
            self.json["language"] = self.json.get("language", "en_US") 
            self.json["theme_color"] = self.json.get("theme_color", "White")
            self.json["high_sensitive"] = self.json.get("high_sensitive", 0)
            self.json["extension_kits"] = self.json.get("extension_kits", 0)
            self.json["cloud_services"] = self.json.get("cloud_services", "None")
            if self.json["high_sensitive"] == 1:
                self.ui.high_sensitivity_switch_Button.setText(self.trans("已開啟"))
                self.ui.high_sensitivity_switch_Button.setStyleSheet("""
                QPushButton{border:none;background-color:rgb(200, 250, 200);border-radius: 10px;}
                QPushButton:hover{background-color:rgb(210, 250, 210);}""")
            if self.json["extension_kits"] == 1:
                self.ui.extension_kit_switch_Button.setText(self.trans("已開啟"))
                self.ui.extension_kit_switch_Button.setStyleSheet("""
                QPushButton{border:none;background-color:rgb(200, 250, 200);border-radius: 10px;}
                QPushButton:hover{background-color:rgb(210, 250, 210);}""")
            if self.json["language"] == "zh_TW":
                self.ui.Language_Traditional_Chinese.setChecked(True)
            elif self.json["language"] == "zh_CN":
                self.ui.Language_Simplified_Chinese.setChecked(True)
            elif self.json["language"] == "en_US":
                self.ui.Language_English.setChecked(True)
            if self.json["theme_color"] == "White":
                self.ui.Theme_White.setChecked(True)
            elif self.json["theme_color"] == "Red":
                self.ui.Theme_Red.setChecked(True)
            elif self.json["theme_color"] == "Green":
                self.ui.Theme_Green.setChecked(True)
            elif self.json["theme_color"] == "Yellow":
                self.ui.Theme_Yellow.setChecked(True)
            elif self.json["theme_color"] == "Blue":
                self.ui.Theme_Blue.setChecked(True)
            elif os.path.exists(self.json["theme_color"]):
                self.ui.Theme_Customize.setChecked(True)
            self.whitelist = []
            if os.path.exists("C:/ProgramData/PYAS/Whitelist.ini"):
                with open("C:/ProgramData/PYAS/Whitelist.ini", "r") as f:
                    self.whitelist = [l.strip() for l in f.readlines()]
            self.blocklist = []
            if os.path.exists("C:/ProgramData/PYAS/Blocklist.ini"):
                with open("C:/ProgramData/PYAS/Blocklist.ini", "r") as f:
                    self.blocklist = [line.strip() for line in f.readlines()]
        except Exception as e:
            self.bug_event(e)

    def init_control(self):
        self.ui.Close_Button.clicked.connect(self.close)
        self.ui.Minimize_Button.clicked.connect(self.showMinimized)
        self.ui.Menu_Button.clicked.connect(self.show_menu)
        self.ui.State_Button.clicked.connect(self.change_state_widget)
        self.ui.Tools_Button.clicked.connect(self.change_tools_widget)    
        self.ui.Virus_Scan_Button.clicked.connect(self.change_scan_widget)
        self.ui.Protection_Button.clicked.connect(self.change_protect_widget)
        self.ui.Virus_Scan_output.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.Virus_Scan_output.customContextMenuRequested.connect(self.Virus_Scan_output_menu)
        self.ui.Virus_Scan_Solve_Button.clicked.connect(self.virus_solve)
        self.ui.Virus_Scan_choose_Button.clicked.connect(self.virus_scan_menu)
        self.ui.Virus_Scan_Break_Button.clicked.connect(self.virus_scan_break)
        self.ui.File_Scan_Button.clicked.connect(self.file_scan)
        self.ui.Path_Scan_Button.clicked.connect(self.path_scan)
        self.ui.Disk_Scan_Button.clicked.connect(self.disk_scan)
        self.ui.System_Process_Manage_Button.clicked.connect(lambda:self.change_tools(self.ui.Process_widget))
        self.ui.Process_Tools_Back.clicked.connect(lambda:self.back_to_tools(self.ui.Process_widget))
        self.ui.Repair_System_Files_Button.clicked.connect(self.repair_system)
        self.ui.Clean_System_Files_Button.clicked.connect(self.clean_system)
        self.ui.Window_Block_Button.clicked.connect(self.get_software_window)
        self.ui.Repair_System_Network_Button.clicked.connect(self.repair_network)
        self.ui.Process_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.Process_list.customContextMenuRequested.connect(self.process_list_menu)
        self.ui.About_Back.clicked.connect(self.ui.About_widget.hide)
        self.ui.Setting_Back.clicked.connect(self.setting_back)
        self.ui.Protection_switch_Button.clicked.connect(self.protect_proc_init)
        self.ui.Protection_switch_Button_2.clicked.connect(self.protect_file_init)
        self.ui.Protection_switch_Button_3.clicked.connect(self.protect_sys_init)
        self.ui.Protection_switch_Button_4.clicked.connect(self.protect_drv_init)
        self.ui.Protection_switch_Button_5.clicked.connect(self.protect_net_init)
        self.ui.high_sensitivity_switch_Button.clicked.connect(self.change_sensitive)
        self.ui.extension_kit_switch_Button.clicked.connect(self.extension_kit)
        self.ui.Add_White_list_Button.clicked.connect(self.add_white_list)
        self.ui.Language_Traditional_Chinese.clicked.connect(self.init_change_lang)
        self.ui.Language_Simplified_Chinese.clicked.connect(self.init_change_lang)
        self.ui.Language_English.clicked.connect(self.init_change_lang)
        self.ui.Theme_White.clicked.connect(self.init_theme_color)
        self.ui.Theme_Customize.clicked.connect(self.init_theme_color)
        self.ui.Theme_Green.clicked.connect(self.init_theme_color)
        self.ui.Theme_Yellow.clicked.connect(self.init_theme_color)
        self.ui.Theme_Blue.clicked.connect(self.init_theme_color)
        self.ui.Theme_Red.clicked.connect(self.init_theme_color)

    def init_config_qtui(self):
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.virus_lock = {}
        self.virus_list = []
        self.virus_list_ui = []
        self.Process_quantity = []
        self.Process_list_all_pid = []
        self.Process_sim = QStringListModel()
        self.Process_Timer = QTimer()
        self.Process_Timer.timeout.connect(self.process_list)
        self.ui.widget_2.lower()
        self.ui.Navigation_Bar.raise_()
        self.ui.Window_widget.raise_()
        self.ui.Virus_Scan_choose_widget.raise_()
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
        self.ui.License_terms.setText('''Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.''')

    def init_change_lang(self):
        try:
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
        self.ui.State_title.setText(self.trans("此裝置已受到防護"))
        self.ui.Window_title.setText(self.trans(f"PYAS Security"))
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
        self.ui.Protection_title_3.setText(self.trans("系統防護"))
        self.ui.Protection_illustrate_3.setText(self.trans("啟用此選項可以修復系統項目"))
        self.ui.Protection_switch_Button_3.setText(self.trans(self.ui.Protection_switch_Button_3.text()))
        self.ui.Protection_title_4.setText(self.trans("驅動防護"))
        self.ui.Protection_illustrate_4.setText(self.trans("啟用此選項可以增強自身防護"))
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
        self.ui.PYAS_Version.setText(self.trans(f"PYAS Security V{self.pyas_version} ({self.pyae_version})"))
        self.ui.GUI_Made_title.setText(self.trans("介面製作:"))
        self.ui.GUI_Made_Name.setText(self.trans("mtkiao"))
        self.ui.Core_Made_title.setText(self.trans("核心製作:"))
        self.ui.Core_Made_Name.setText(self.trans("87owo"))
        self.ui.Testers_title.setText(self.trans("特別感謝:"))
        self.ui.Testers_Name.setText(self.trans("0sha0"))
        self.ui.PYAS_URL_title.setText(self.trans("官方網站:"))
        self.ui.PYAS_URL.setText(self.trans("<html><head/><body><p><a href=\"https://github.com/87owo/PYAS\"><span style=\" text-decoration: underline; color:#000000;\">https://github.com/87owo/PYAS</span></a></p></body></html>"))
        self.ui.high_sensitivity_title.setText(self.trans("高靈敏度模式"))
        self.ui.high_sensitivity_illustrate.setText(self.trans("啟用此選項可以提高掃描引擎靈敏度"))
        self.ui.high_sensitivity_switch_Button.setText(self.trans(self.ui.high_sensitivity_switch_Button.text()))
        self.ui.extension_kit_title.setText(self.trans("擴展掃描引擎"))
        self.ui.extension_kit_illustrate.setText(self.trans("啟用此選項可以使用第三方擴展套件"))
        self.ui.extension_kit_switch_Button.setText(self.trans(self.ui.extension_kit_switch_Button.text()))
        self.ui.Add_White_list_title.setText(self.trans("增加到白名單"))
        self.ui.Add_White_list_illustrate.setText(self.trans("此選項可以選擇檔案並增加到白名單"))
        self.ui.Add_White_list_Button.setText(self.trans(self.ui.Add_White_list_Button.text()))
        self.ui.Add_White_list_Button.setText(self.trans("選擇"))
        self.ui.Theme_title.setText(self.trans("顯色主題"))
        self.ui.Theme_illustrate.setText(self.trans("請選擇主題"))
        self.ui.Theme_Customize.setText(self.trans("自定主題"))
        self.ui.Theme_White.setText(self.trans("白色主題"))
        self.ui.Theme_Yellow.setText(self.trans("黃色主題"))
        self.ui.Theme_Red.setText(self.trans("紅色主題"))
        self.ui.Theme_Green.setText(self.trans("綠色主題"))
        self.ui.Theme_Blue.setText(self.trans("藍色主題"))
        self.ui.Setting_Back.setText(self.trans("返回"))
        self.ui.Language_title.setText(self.trans("顯示語言"))
        self.ui.Language_illustrate.setText(self.trans("請選擇語言"))
        self.ui.License_terms_title.setText(self.trans("許可條款:"))

    def init_theme_color(self):
        try:
            if self.ui.Theme_White.isChecked():
                self.json["theme_color"] = "White"
                self.ui.State_icon.setPixmap(QPixmap(":/icon/Check.png"))
                self.ui.Window_widget.setStyleSheet("QWidget#Window_widget {background-color:rgb(240,240,240);}")
                self.ui.Navigation_Bar.setStyleSheet("QWidget#Navigation_Bar {background-color:rgb(230,230,230);}")
            elif self.ui.Theme_Red.isChecked():
                self.json["theme_color"] = "Red"
                self.ui.State_icon.setPixmap(QPixmap(":/icon/Check.png"))
                self.ui.Window_widget.setStyleSheet("QWidget#Window_widget {background-color:rgb(250,230,230);}")
                self.ui.Navigation_Bar.setStyleSheet("QWidget#Navigation_Bar {background-color:rgb(250,220,220);}")
            elif self.ui.Theme_Green.isChecked():
                self.json["theme_color"] = "Green"
                self.ui.State_icon.setPixmap(QPixmap(":/icon/Check.png"))
                self.ui.Window_widget.setStyleSheet("QWidget#Window_widget {background-color:rgb(230,250,230);}")
                self.ui.Navigation_Bar.setStyleSheet("QWidget#Navigation_Bar {background-color:rgb(220,250,220);}")
            elif self.ui.Theme_Blue.isChecked():
                self.json["theme_color"] = "Blue"
                self.ui.State_icon.setPixmap(QPixmap(":/icon/Check.png"))
                self.ui.Window_widget.setStyleSheet("QWidget#Window_widget {background-color:rgb(230,250,250);}")
                self.ui.Navigation_Bar.setStyleSheet("QWidget#Navigation_Bar {background-color:rgb(220,250,250);}")
            elif self.ui.Theme_Yellow.isChecked():
                self.json["theme_color"] = "Yellow"
                self.ui.State_icon.setPixmap(QPixmap(":/icon/Check.png"))
                self.ui.Window_widget.setStyleSheet("QWidget#Window_widget {background-color:rgb(250,250,230);}")
                self.ui.Navigation_Bar.setStyleSheet("QWidget#Navigation_Bar {background-color:rgb(250,250,220);}")
            elif self.ui.Theme_Customize.isChecked():
                if not os.path.exists(os.path.join(self.json["theme_color"],"Color.ini")):
                    path = str(QFileDialog.getExistingDirectory(self,self.trans("自定主題"),"C:/"))
                    if path and os.path.exists(os.path.join(path,"Color.ini")):
                        self.json["theme_color"] = path
                with open(os.path.join(self.json["theme_color"],"Color.ini"), "r") as f:
                    self.themecolor = [line.strip() for line in f.readlines()]
                self.ui.Window_widget.setStyleSheet(self.themecolor[0])
                self.ui.Navigation_Bar.setStyleSheet(self.themecolor[1])
                file = os.path.join(self.json["theme_color"],"Check.png")
                self.ui.State_icon.setPixmap(QPixmap(file))
            self.write_config(self.json)
        except:
            self.ui.Theme_White.setChecked(True)
            self.json["theme_color"] = "White"
            self.ui.State_icon.setPixmap(QPixmap(":/icon/Check.png"))
            self.ui.Window_widget.setStyleSheet("QWidget#Window_widget {background-color:rgb(240,240,240);}")
            self.ui.Navigation_Bar.setStyleSheet("QWidget#Navigation_Bar {background-color:rgb(230,230,230);}")

    def change_animation(self,widget):
        x, y = 170, widget.pos().y()
        self.anim = QPropertyAnimation(widget, b"geometry")
        widget.setGeometry(QRect(x - 100,y, 671, 481))
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
        # animation for change opacity
        if self.opacity.i <= 1:
            self.opacity.i += 0.05
            self.opacity.setOpacity(self.opacity.i)
        else:
            self.timer.stop()

    def change_animation_4(self,widget,time,ny,ny2):
        # animation for virus_scan_menu
        x, y = widget.pos().x(), widget.pos().y()
        self.anim4 = QPropertyAnimation(widget, b"geometry")
        self.anim4.setDuration(time)
        self.anim4.setStartValue(QRect(x, y, 131, ny))
        self.anim4.setEndValue(QRect(x, y, 131, ny2))
        self.anim4.start()

    def change_animation_5(self,widget,x,y,nx,ny):
        # animation for show_menu
        self.anim = QPropertyAnimation(widget, b"geometry")
        widget.setGeometry(QRect(x,y - 45, nx,ny))
        self.anim.setKeyValueAt(0.2, QRect(x,y - 30,nx,ny))
        self.anim.setKeyValueAt(0.4, QRect(x,y - 10,nx,ny))
        self.anim.setKeyValueAt(0.7, QRect(x,y - 3,nx,ny))
        self.anim.setKeyValueAt(1, QRect(x,y,nx,ny))
        self.anim.start()

    def change_state_widget(self):
        # Toggle interface to hide or show elements
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
        # Toggle interface to hide or show elements
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
        # Toggle interface to hide or show elements
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
        # Toggle interface to hide or show elements
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
        # Toggle interface to hide or show elements
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
        # Toggle interface to hide or show elements
        widget.hide()
        if widget == self.ui.Process_widget:
            self.Process_Timer.stop()
        self.change_animation_3(self.ui.Tools_widget,0.5)
        self.change_animation(self.ui.Tools_widget)
        self.ui.Tools_widget.show()

    def mousePressEvent(self, event):
        # Drag window opacity
        def update_opacity():
            if self.pyas_opacity > 80 and self.m_flag == True:
                self.pyas_opacity -= 1
                self.setWindowOpacity(self.pyas_opacity/100)
            else:
                self.timer.stop()
        # Check drag window area
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
            # Drag window
            if Qt.LeftButton and self.m_flag:
                self.move(QMouseEvent.globalPos()-self.m_Position)
                QApplication.processEvents()
                QMouseEvent.accept()
        except:
            pass

    def mouseReleaseEvent(self, QMouseEvent):
        # restore window opacity
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

    def init_show_pyas(self):
        # form init_startup function :)
        def update_opacity():
            if self.pyas_opacity <= 100:
                self.pyas_opacity += 2
                self.setWindowOpacity(self.pyas_opacity/100)
            else:
                self.timer.stop()
        self.pyas_opacity = 0
        self.show()
        self.timer = QTimer()
        self.timer.timeout.connect(update_opacity)
        self.timer.start(2)
        self.init_change_lang()
        self.init_theme_color()

    def init_hide_pyas(self):
        # hide to tray_icon
        def update_opacity():
            if self.pyas_opacity >= 0:
                self.pyas_opacity -= 2
                self.setWindowOpacity(self.pyas_opacity/100)
            else:
                self.timer.stop()
                self.hide()
        self.timer = QTimer()
        self.timer.timeout.connect(update_opacity)
        self.timer.start(2)

    def showMinimized(self):
        # form init_hide_pyas function
        if self.block_window:
            self.init_hide_pyas()
            self.send_notify(self.trans("PYAS 已最小化到系統托盤圖標"))

    def closeEvent(self, event):
        # quit ui question
        if self.question_event("您確定要退出 PYAS 和所有防護嗎?"):
            Popen("sc stop PYAS_Driver", shell=True, stdout=PIPE, stderr=PIPE).wait()
            self.first_startup = True
            self.protect_proc_init()
            self.protect_file_init()
            self.protect_sys_init()
            self.protect_drv_init()
            self.protect_net_init()
            self.virus_scan_break()
            event.accept()
        else:
            event.ignore()

    def bug_event(self, text):
        try:
            # bug event message
            print(f"[Error] > {text}")
            if self.first_startup != True:
                QMessageBox.critical(self, "Error", str(text), QMessageBox.Ok)
        except:
            pass

    def info_event(self, text):
        try:
            # info event message
            print(f"[Info] > {text}")
            if self.first_startup != True:
                QMessageBox.information(self, "Info", self.trans(str(text)), QMessageBox.Ok)
        except:
            pass

    def question_event(self, text):
        try:
            # question event message
            print(f"[Quest] > {text}")
            if self.first_startup != True:
                return QMessageBox.question(self, "Quest", self.trans(str(text)),QMessageBox.Yes|QMessageBox.No) == 16384
        except:
            return False

    def send_notify(self, text, notify_bar=True):
        try:
            # send system notification
            now_time = time.strftime('%Y-%m-%d %H:%M:%S')
            print(f"[Notify] > [{now_time}] {text}")
            QMetaObject.invokeMethod(self.ui.State_output, "append", Qt.QueuedConnection, Q_ARG(str, f"[{now_time}] {text}"))
            if self.first_startup == False and notify_bar == True:
                self.tray_icon.showMessage(now_time, text, 5000)
        except:
            pass

    def show_menu(self):
        # menu for settings / about / update
        self.WindowMenu = QMenu()
        Main_Settings = QAction(self.trans("設定"),self)
        #Main_Update = QAction(self.trans("更新"),self)
        Main_About = QAction(self.trans("關於"),self)
        self.WindowMenu.addAction(Main_Settings)
        #self.WindowMenu.addAction(Main_Update)
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
        #if Qusetion == Main_Update:
            #self.update_database()

    def update_database(self):
        try:
            # Deprecated functionality :(
            if self.question_event("您確定要更新數據庫嗎?"):
                pass
        except Exception as e:
            self.bug_event(e)

    def change_sensitive(self):
        sw_state = self.ui.high_sensitivity_switch_Button.text()
        if sw_state == self.trans("已開啟"):
            # close high sensitive mode
            self.json["high_sensitive"] = 0
            self.ui.high_sensitivity_switch_Button.setText(self.trans("已關閉"))
            self.ui.high_sensitivity_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgb(230,230,230);border-radius: 10px;}
            QPushButton:hover{background-color:rgb(220,220,220);}""")
        elif self.question_event("此選項可能會誤報檔案，您確定要開啟嗎?"):
            # open high sensitive mode
            self.json["high_sensitive"] = 1
            self.ui.high_sensitivity_switch_Button.setText(self.trans("已開啟"))
            self.ui.high_sensitivity_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgb(200,250,200);border-radius: 10px;}
            QPushButton:hover{background-color:rgb(210,250,210);}""")
        self.write_config(self.json)

    def extension_kit(self):
        sw_state = self.ui.extension_kit_switch_Button.text()
        if sw_state == self.trans("已開啟"):
            # close extension kit mode
            self.json["extension_kits"] = 0
            self.ui.extension_kit_switch_Button.setText(self.trans("已關閉"))
            self.ui.extension_kit_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgb(230,230,230);border-radius: 10px;}
            QPushButton:hover{background-color:rgb(220,220,220);}""")
        else:
            # open extension kit mode
            self.json["extension_kits"] = 1
            self.ui.extension_kit_switch_Button.setText(self.trans("已開啟"))
            self.ui.extension_kit_switch_Button.setStyleSheet("""
            QPushButton{border:none;background-color:rgb(200,250,200);border-radius: 10px;}
            QPushButton:hover{background-color:rgb(210,250,210);}""")
        self.write_config(self.json)

    def init_scan(self):
        try:
            self.ui.Virus_Scan_text.setText(self.trans("正在初始化中"))
            QApplication.processEvents()
            try:
                # Clear locked files
                for file in self.virus_list:
                    self.lock_file(file, False)
            except:
                pass
            # init scan config
            self.scan_file = True
            self.virus_lock = {}
            self.virus_list = []
            self.virus_list_ui = []
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
                pyperclip.copy(item_row.replace("/", "\\"))
        menu = QMenu()
        copyPath = menu.addAction(self.trans("複製路徑"))
        copyPath.triggered.connect(lambda: copyPathFunc())
        menu.exec_(self.ui.Virus_Scan_output.mapToGlobal(point))

    def lock_file(self, file, lock):
        try:
            # lock file using msvcrt
            if lock:
                self.virus_lock[file] = os.open(file, os.O_RDWR)
                msvcrt.locking(self.virus_lock[file], msvcrt.LK_NBRLCK, os.path.getsize(file))
            else:
                # unlock file
                msvcrt.locking(self.virus_lock[file], msvcrt.LK_UNLCK, os.path.getsize(file))
                os.close(self.virus_lock[file])
        except:
            pass

    def virus_solve(self):
        try:
            self.ui.Virus_Scan_Solve_Button.hide()
            for file in self.virus_list:
                try:
                    # delete file
                    if self.ui.Virus_Scan_output.findItems(file, Qt.MatchContains)[0].checkState() == Qt.Checked:
                        QMetaObject.invokeMethod(self.ui.Virus_Scan_title, "setText",
                        Qt.QueuedConnection, Q_ARG(str, self.trans("正在刪除")))
                        QMetaObject.invokeMethod(self.ui.Virus_Scan_text, "setText",
                        Qt.QueuedConnection, Q_ARG(str, file))
                        QApplication.processEvents()
                        self.lock_file(file, False)
                        self.ransom_counts = 0
                        os.remove(file)
                    else:
                        self.lock_file(file, False)
                except:
                    continue
            self.ui.Virus_Scan_output.clear()
            QMetaObject.invokeMethod(self.ui.Virus_Scan_title, "setText",
            Qt.QueuedConnection, Q_ARG(str, self.trans("病毒掃描")))
            QMetaObject.invokeMethod(self.ui.Virus_Scan_text, "setText",
            Qt.QueuedConnection, Q_ARG(str, self.trans("刪除成功")))
        except Exception as e:
            self.bug_event(e)

    def write_scan(self, state, file):
        try:
            if state and file:
                self.lock_file(file, True)
                self.virus_list.append(file)
                self.virus_list_ui.append(f"[{state}] {file}")
                item = QListWidgetItem()
                item.setText(f"[{state}] {file}")
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                item.setCheckState(Qt.Checked)
                self.ui.Virus_Scan_output.addItem(item)
                self.send_notify(self.trans(f"發現病毒: ")+file, False)
        except:
            pass

    def answer_scan(self):
        try:
            QMetaObject.invokeMethod(self.ui.Virus_Scan_title, "setText",
            Qt.QueuedConnection, Q_ARG(str, self.trans("病毒掃描")))
            if self.virus_list:
                self.ui.Virus_Scan_Solve_Button.show()
                self.ui.Virus_Scan_Break_Button.hide()
                self.ui.Virus_Scan_choose_Button.show()
                text = self.trans(f"當前發現 {len(self.virus_list)} 個病毒")
            else:
                self.virus_scan_break()
                text = self.trans("當前未發現病毒")
            self.scan_thread.join()
            QMetaObject.invokeMethod(self.ui.Virus_Scan_text, "setText",
            Qt.QueuedConnection, Q_ARG(str, text))
            self.send_notify(text)
            gc.collect()
        except Exception as e:
            self.bug_event(e)

    def virus_scan_break(self):
        self.scan_file = False
        self.ui.Virus_Scan_Break_Button.hide()
        self.ui.Virus_Scan_choose_Button.show()
        QMetaObject.invokeMethod(self.ui.Virus_Scan_title, "setText",
        Qt.QueuedConnection, Q_ARG(str, self.trans("病毒掃描")))
        QMetaObject.invokeMethod(self.ui.Virus_Scan_text, "setText",
        Qt.QueuedConnection, Q_ARG(str, self.trans("請選擇掃描方式")))

    def virus_scan_menu(self):
        if self.ui.Virus_Scan_choose_widget.isHidden():
            self.ui.Virus_Scan_choose_widget.show()
            self.change_animation_4(self.ui.Virus_Scan_choose_widget,100,0,101)
        else:
            self.ui.Virus_Scan_choose_widget.hide()

    def file_scan(self):
        try:
            file = str(QFileDialog.getOpenFileName(self,self.trans("病毒掃描"),"C:/")[0])
            if file and file not in self.whitelist and file != self.pyas:
                self.init_scan()
                self.scan_thread = Thread(target=self.write_scan, args=(self.start_scan(file),file,), daemon=True)
                self.scan_thread.start()
                while self.scan_thread.is_alive():
                    QApplication.processEvents()
                self.answer_scan()
        except Exception as e:
            self.bug_event(e)
            self.virus_scan_break()

    def path_scan(self):
        try:
            path = str(QFileDialog.getExistingDirectory(self,self.trans("病毒掃描"),"C:/"))
            if path:
                self.init_scan()
                self.scan_thread = Thread(target=self.traverse_path, args=(path,), daemon=True)
                self.scan_thread.start()
                while self.scan_thread.is_alive():
                    QApplication.processEvents()
                self.answer_scan()
        except Exception as e:
            self.bug_event(e)
            self.virus_scan_break()

    def disk_scan(self):
        try:
            self.init_scan()
            for d in range(26):
                if os.path.exists(f"{chr(65+d)}:/"):
                    self.scan_thread = Thread(target=self.traverse_path, args=(f"{chr(65+d)}:/",), daemon=True)
                    self.scan_thread.start()
                    while self.scan_thread.is_alive():
                        QApplication.processEvents()
            self.answer_scan()
        except Exception as e:
            self.bug_event(e)
            self.virus_scan_break()

    def traverse_path(self, file_path):
        for fd in os.listdir(file_path):
            try:
                file = str(os.path.join(file_path,fd)).replace("\\", "/")
                if self.scan_file == False:
                    break
                elif os.path.isdir(file):
                    self.traverse_path(file)
                elif file != self.pyas and file not in self.whitelist:
                    QMetaObject.invokeMethod(self.ui.Virus_Scan_title, "setText",
                    Qt.QueuedConnection, Q_ARG(str, self.trans("正在掃描")))
                    QMetaObject.invokeMethod(self.ui.Virus_Scan_text, "setText",
                    Qt.QueuedConnection, Q_ARG(str, file))
                    self.write_scan(self.start_scan(file),file)
                gc.collect()
            except:
                pass

    def start_scan(self, file):
        try:
            if os.path.exists(file):
                self.send_notify(self.trans(f"正在掃描: ")+file, False)
            label, level = self.model.dl_scan(file)
            if label and label in self.model.detect:
                if self.json["high_sensitive"]:
                    return "Virus/Deep-Learning"
                elif level >= self.model.values:
                    return "Virus/Deep-Learning"
            if self.json["extension_kits"]:
                if self.rules.yr_scan(file):
                    return "Virus/Yara-Detected"
            return False
        except:
            return False

    def repair_system(self):
        try:
            if self.question_event("您確定要修復系統檔案嗎?"):
                self.repair_system_wallpaper()
                self.repair_system_restrict()
                self.repair_system_file_type()
                self.repair_system_file_icon()
                self.repair_system_image()
                self.info_event("修復系統檔案成功")
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
                        name = self.track_proc.name()
                        if "cmd.exe" not in name and "powershell" not in name:
                            self.kill_process("註冊表攔截", *self.track_proc)
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
            if self.question_event("您確定要清理系統垃圾嗎?"):
                self.total_deleted_size = 0
                self.traverse_temp(f"C:/Users/{os.getlogin()}/AppData/Local/Temp/")
                self.traverse_temp(f"C:/Windows/Temp/")
                self.traverse_temp(f"C:/$Recycle.Bin/")
                self.info_event(f"成功清理了 {self.total_deleted_size} 位元的系統垃圾")
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
                    self.ransom_counts = 0
                    os.remove(file)
                    self.total_deleted_size += file_size
            except:
                continue

    def add_white_list(self):
        try:
            file = str(QFileDialog.getOpenFileName(self,self.trans("增加到白名單"),"C:/")[0]).replace("\\", "/")
            if file and file not in self.whitelist:
                if self.question_event("您確定要增加到白名單嗎?"):
                    self.whitelist.append(file)
                    with open("C:/ProgramData/PYAS/Whitelist.ini", "a+") as f:
                        f.write(f"{file}\n")
                    self.info_event(f"成功增加到白名單: "+file)
            elif file and self.question_event("您確定要取消增加到白名單嗎?"):
                self.whitelist.remove(file)
                with open("C:/ProgramData/PYAS/Whitelist.ini", "w") as f:
                    for white_file in self.whitelist:
                        f.write(f'{white_file}\n')
                self.info_event(f"成功取消增加到白名單: "+file)
        except Exception as e:
            self.bug_event(e)

    def get_software_window(self):
        try:
            self.block_window = False
            if self.question_event("請選擇要攔截的軟體彈窗"):
                while not self.block_window:
                    QApplication.processEvents()
                    window_name = str(win32gui.GetWindowText(win32gui.GetForegroundWindow()))
                    if window_name not in ["","PYAS",self.trans("警告")]:
                        if window_name not in self.blocklist:
                            if self.question_event(f"您確定要攔截 {window_name} 嗎?"):
                                self.blocklist.append(window_name)
                                with open("C:/ProgramData/PYAS/Blocklist.ini", "a+") as f:
                                    f.write(f'{window_name}\n')
                                self.info_event(f"成功增加到彈窗攔截: "+window_name)
                        elif self.question_event(f"您確定要取消攔截 {window_name} 嗎?"):
                            self.blocklist.remove(window_name)
                            with open("C:/ProgramData/PYAS/Blocklist.ini", "w") as f:
                                for block_name in self.blocklist:
                                    f.write(f'{block_name}\n')
                            self.info_event(f"成功取消彈窗攔截: "+window_name)
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
                time.sleep(0.2)
                for window_name in self.blocklist:
                    win32gui.PostMessage(win32gui.FindWindow(None, window_name), 274, 61536, 0)
            except:
                pass

    def repair_network(self):
        try:
            if self.question_event("您確定要修復系統網路嗎?"):
                Popen("netsh winsock reset", shell=True, stdout=PIPE, stderr=PIPE).wait()
                if self.question_event("使用此選項需要重啟，您確定要重啟嗎?"):
                    Popen("shutdown -r -t 0", shell=True, stdout=PIPE, stderr=PIPE).wait()
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
                        file = p.exe().replace("\\", "/")
                        if file == self.pyas:
                            self.close()
                        else:
                            p.kill()
        except:
            pass

    def protect_proc_init(self):
        try:
            if self.ui.Protection_switch_Button.text() == self.trans("已開啟"):
                self.ui.Protection_switch_Button.setText(self.trans("已關閉"))
                self.ui.Protection_switch_Button.setStyleSheet("""
                QPushButton{border:none;background-color:rgb(230, 230, 230);border-radius: 10px;}
                QPushButton:hover{background-color:rgb(220, 220, 220);}""")
                self.proc_protect = False
            else:
                self.proc_protect = True
                self.ui.Protection_switch_Button.setText(self.trans("已開啟"))
                self.ui.Protection_switch_Button.setStyleSheet("""
                QPushButton{border:none;background-color:rgb(200, 250, 200);border-radius: 10px;}
                QPushButton:hover{background-color:rgb(210, 250, 210);}""")
                Thread(target=self.protect_proc_thread, daemon=True).start()
        except Exception as e:
            self.bug_event(self.trans(f"進程防護開啟失敗: ")+str(e))

    def protect_file_init(self):
        try:
            if self.ui.Protection_switch_Button_2.text() == self.trans("已開啟"):
                self.ui.Protection_switch_Button_2.setText(self.trans("已關閉"))
                self.ui.Protection_switch_Button_2.setStyleSheet("""
                QPushButton{border:none;background-color:rgb(230, 230, 230);border-radius: 10px;}
                QPushButton:hover{background-color:rgb(220, 220, 220);}""")
                self.file_protect = False
            else:
                self.file_protect = True
                self.ui.Protection_switch_Button_2.setText(self.trans("已開啟"))
                self.ui.Protection_switch_Button_2.setStyleSheet("""
                QPushButton{border:none;background-color:rgb(200, 250, 200);border-radius: 10px;}
                QPushButton:hover{background-color:rgb(210, 250, 210);}""")
                Thread(target=self.protect_file_thread, daemon=True).start()
        except Exception as e:
            self.bug_event(self.trans(f"檔案防護開啟失敗: ")+str(e))

    def protect_sys_init(self):
        try:
            if self.ui.Protection_switch_Button_3.text() == self.trans("已開啟"):
                self.ui.Protection_switch_Button_3.setText(self.trans("已關閉"))
                self.ui.Protection_switch_Button_3.setStyleSheet("""
                QPushButton{border:none;background-color:rgb(230, 230, 230);border-radius: 10px;}
                QPushButton:hover{background-color:rgb(220, 220, 220);}""")
                self.sys_protect = False
            else:
                self.sys_protect = True
                self.ui.Protection_switch_Button_3.setText(self.trans("已開啟"))
                self.ui.Protection_switch_Button_3.setStyleSheet("""
                QPushButton{border:none;background-color:rgb(200, 250, 200);border-radius: 10px;}
                QPushButton:hover{background-color:rgb(210, 250, 210);}""")
                Thread(target=self.protect_boot_thread, daemon=True).start()
                Thread(target=self.protect_reg_thread, daemon=True).start()
        except Exception as e:
            self.bug_event(self.trans(f"系統防護開啟失敗: ")+str(e))

    def protect_drv_init(self):
        try:
            file_path = os.path.join(self.dir, "Driver").replace("\\", "/")
            if os.path.exists(file_path):
                if self.ui.Protection_switch_Button_4.text() == self.trans("已開啟"):
                    result = Popen("sc stop PYAS_Driver", shell=True, stdout=PIPE, stderr=PIPE).wait()
                    if not self.first_startup:
                        if result == 0 or result == 577:
                            if self.question_event("使用此選項需要重啟，您確定要重啟嗎?"):
                                Popen(f'"{file_path}/Uninstall_Driver.bat"', shell=True, stdout=PIPE, stderr=PIPE)
                            else:
                                Popen("sc start PYAS_Driver", shell=True, stdout=PIPE, stderr=PIPE).wait()
                    if result == 1062 or result == 1060:
                        self.ui.Protection_switch_Button_4.setText(self.trans("已關閉"))
                        self.ui.Protection_switch_Button_4.setStyleSheet("""
                        QPushButton{border:none;background-color:rgb(230, 230, 230);border-radius: 10px;}
                        QPushButton:hover{background-color:rgb(220, 220, 220);}""")
                else:
                    result = Popen("sc start PYAS_Driver", shell=True, stdout=PIPE, stderr=PIPE).wait()
                    if not self.first_startup:
                        if result == 1060 or result == 3 or result == 577:
                            if self.question_event("此選項可能會與其他軟體不兼容，您確定要開啟嗎?"):
                                Popen("sc delete PYAS_Driver", shell=True, stdout=PIPE, stderr=PIPE).wait()
                                Popen(f'"{file_path}/Install_Driver.bat"', shell=True, stdout=PIPE, stderr=PIPE)
                            else:
                                Popen("sc stop PYAS_Driver", shell=True, stdout=PIPE, stderr=PIPE).wait()
                    if result == 0 or result == 1056:
                        self.ui.Protection_switch_Button_4.setText(self.trans("已開啟"))
                        self.ui.Protection_switch_Button_4.setStyleSheet("""
                        QPushButton{border:none;background-color:rgb(200, 250, 200);border-radius: 10px;}
                        QPushButton:hover{background-color:rgb(210, 250, 210);}""")
            elif not self.first_startup:
                self.bug_event(self.trans(f"驅動防護檔案丟失: ")+str(file_path))
        except Exception as e:
            self.bug_event(self.trans(f"驅動防護開啟失敗: ")+str(e))

    def protect_net_init(self):
        try:
            if self.ui.Protection_switch_Button_5.text() == self.trans("已開啟"):
                self.ui.Protection_switch_Button_5.setText(self.trans("已關閉"))
                self.ui.Protection_switch_Button_5.setStyleSheet("""
                QPushButton{border:none;background-color:rgb(230, 230, 230);border-radius: 10px;}
                QPushButton:hover{background-color:rgb(220, 220, 220);}""")
                self.net_protect = False
            else:
                self.net_protect = True
                self.ui.Protection_switch_Button_5.setText(self.trans("已開啟"))
                self.ui.Protection_switch_Button_5.setStyleSheet("""
                QPushButton{border:none;background-color:rgb(200, 250, 200);border-radius: 10px;}
                QPushButton:hover{background-color:rgb(210, 250, 210);}""")
                Thread(target=self.protect_net_thread, daemon=True).start()
        except Exception as e:
            self.bug_event(self.trans(f"網路防護開啟失敗: ")+str(e))

    def protect_proc_thread(self):
        while self.proc_protect:
            time.sleep(0.01)
            new_process = set()
            for p in psutil.process_iter():
                new_process.add(p.pid)
            for pid in new_process - self.exist_process:
                try:
                    p = psutil.Process(pid)
                    self.lock_process(p, True)
                    self.handle_new_process(p)
                    self.lock_process(p, False)
                    gc.collect()
                except:
                    pass
            self.exist_process = new_process
        if self.ui.Protection_switch_Button.text() == self.trans("已開啟"):
            self.send_notify(self.trans(f"竄改警告: self.proc_protect"), False)

    def handle_new_process(self, p):
        try:
            name, file, cmd = p.name(), p.exe().replace("\\", "/"), p.cmdline()
            if file != self.pyas and file not in self.whitelist:
                if "powershell" in name:
                    file = str(cmd[-1].split("'")[-2]).replace("\\", "/")
                elif "cmd.exe" in name:
                    file = str(" ".join(cmd[2:])).replace("\\", "/")
                elif ":/Windows" in file:
                    file = str(cmd[-1]).replace("\\", "/")
                if self.start_scan(file):
                    self.kill_process("病毒攔截", p, file, False)
                elif self.load_scan(p):
                    self.kill_process("加載攔截", p, file, False)
                elif ":/Windows" not in file and ":/Program" not in file:
                    if os.path.exists(file):
                        self.track_proc = p, file, True
        except:
            pass

    def load_scan(self, p):
        try:
            for entry in p.memory_maps():
                file = str(entry.path).replace("\\", "/")
                if ":/Windows" not in file and file not in self.whitelist:
                    ftype = str(f".{file.split('.')[-1]}").lower()
                    if ftype not in [".exe"] and self.start_scan(file):
                        return True
            return False
        except:
            return False

    def memory_scan(self, p):
        try:
            memory_bytes = {}
            m = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, p.pid)
            for memory_range in p.memory_maps(grouped=False):
                base_addr = int(memory_range.addr, 16)
                buffer = ctypes.create_string_buffer(memory_range.rss)
                if ctypes.windll.kernel32.ReadProcessMemory(m, ctypes.c_void_p(base_addr),
                    buffer, memory_range.rss, ctypes.byref(ctypes.c_size_t(0))):
                    file = str(memory_range.path).replace("\\", "/")
                    memory_bytes.setdefault(file, bytearray()).extend(buffer.raw)
            for file, data in memory_bytes.items():
                ftype = str(f".{file.split('.')[-1]}").lower()
                if ":/Windows" not in file and file not in self.whitelist:
                    if self.start_scan(file) or self.start_scan(bytes(data)):
                        return True
            ctypes.windll.kernel32.CloseHandle(m)
            return False
        except:
            return False

    def lock_process(self, p, lock):
        if lock:
            p.suspend()
        else:
            p.resume()

    def kill_process(self, info, p, target, relation):
        try:
            target = target.replace("\\", "/")
            if relation == False:
                p.kill()
            elif relation == True:
                for p in psutil.process_iter():
                    try:
                        name, file, cmd = p.name(), p.exe(), p.cmdline()
                        if "powershell" in name:
                            file = str(cmd[-1].split("'")[-2])
                        elif "cmd.exe" in name:
                            file = str(" ".join(cmd[2:]))
                        elif ":/Windows" in file.replace("\\", "/"):
                            file = str(cmd[-1])
                        if target == file.replace("\\", "/"):
                            p.kill()
                    except:
                        pass
            self.send_notify(self.trans(f"{info}: ")+target, True)
            self.track_proc = None
        except:
            self.track_proc = None

    def protect_file_thread(self):
        hDir = win32file.CreateFile("C:/",win32con.GENERIC_READ,win32con.FILE_SHARE_READ|win32con.FILE_SHARE_WRITE|win32con.FILE_SHARE_DELETE,None,win32con.OPEN_EXISTING,win32con.FILE_FLAG_BACKUP_SEMANTICS,None)
        self.ransom_counts = 0
        while self.file_protect:
            for action, file in win32file.ReadDirectoryChangesW(hDir,10485760,True,win32con.FILE_NOTIFY_CHANGE_FILE_NAME|win32con.FILE_NOTIFY_CHANGE_DIR_NAME|win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES|win32con.FILE_NOTIFY_CHANGE_SIZE|win32con.FILE_NOTIFY_CHANGE_LAST_WRITE|win32con.FILE_NOTIFY_CHANGE_SECURITY,None,None):
                try:
                    fpath = str(f"C:/{file}").replace("\\", "/")
                    ftype = str(f".{fpath.split('.')[-1]}").lower()
                    if self.ransom_counts >= 5 and self.track_proc:
                        self.ransom_counts = 0
                        self.kill_process("勒索攔截", *self.track_proc)
                    elif ":/Windows" in fpath and "/Temp/" not in fpath:
                        if action == 2 and ftype in alist:
                            self.ransom_counts += 1
                        elif action == 4 and ftype in alist:
                            self.ransom_counts += 1
                    elif ":/Users" in fpath and "/AppData/" not in fpath:
                        if action == 2 and ftype in alist:
                            self.ransom_counts += 1
                        elif action == 4 and ftype in alist:
                            self.ransom_counts += 1
                    if action == 3 and ftype in slist and self.start_scan(fpath):
                        self.ransom_counts = 0
                        os.remove(fpath)
                        self.send_notify(self.trans("病毒刪除: ")+fpath, True)
                except:
                    pass
        if self.ui.Protection_switch_Button_2.text() == self.trans("已開啟"):
            self.send_notify(self.trans(f"竄改警告: self.file_protect"), False)

    def protect_boot_thread(self):
        while self.sys_protect and self.mbr_value:
            try:
                time.sleep(0.2)
                with open(r"\\.\PhysicalDrive0", "r+b") as f:
                    if self.mbr_value[510:512] != b'\x55\xAA':
                        self.kill_process("引導攔截", *self.track_proc)
                    elif f.read(512) != self.mbr_value:
                        f.seek(0)
                        f.write(self.mbr_value)
                        self.kill_process("引導攔截", *self.track_proc)
            except:
                self.kill_process("引導攔截", *self.track_proc)
        if self.ui.Protection_switch_Button_3.text() == self.trans("已開啟"):
            self.send_notify(self.trans(f"竄改警告: self.sys_protect (boot)"), False)

    def protect_reg_thread(self):
        while self.sys_protect:
            try:
                time.sleep(0.2)
                self.repair_system_image()
                self.repair_system_restrict()
                self.repair_system_file_type()
                self.repair_system_file_icon()
            except:
                pass
        if self.ui.Protection_switch_Button_3.text() == self.trans("已開啟"):
            self.send_notify(self.trans(f"竄改警告: self.sys_protect (reg)"), False)

    def protect_net_thread(self):
        while self.net_protect:
            try:
                time.sleep(0.2)
                for conn in self.track_proc[0].connections(kind='inet'):
                    if conn.raddr.ip in self.rules.network:
                        self.kill_process("網路攔截", *self.track_proc)
            except:
                pass
        if self.ui.Protection_switch_Button_5.text() == self.trans("已開啟"):
            self.send_notify(self.trans(f"竄改警告: self.net_protect"), False)

if __name__ == '__main__':
    QCoreApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    QGuiApplication.setAttribute(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    MainWindow_Controller()
    sys.exit(app.exec_())
