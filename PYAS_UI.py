from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(851, 541)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        MainWindow.setFont(font)
        MainWindow.setFocusPolicy(QtCore.Qt.TabFocus)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("Library/PYAS/Icon/ICON.ico"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        MainWindow.setWindowIcon(icon)
        MainWindow.setIconSize(QtCore.QSize(24, 24))
        MainWindow.setToolButtonStyle(QtCore.Qt.ToolButtonIconOnly)
        MainWindow.setDocumentMode(False)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.centralwidget.setFont(font)
        self.centralwidget.setStyleSheet("")
        self.centralwidget.setObjectName("centralwidget")
        self.widget = QtWidgets.QWidget(self.centralwidget)
        self.widget.setGeometry(QtCore.QRect(0, 0, 851, 541))
        self.widget.setObjectName("widget")
        self.Setting_widget = QtWidgets.QWidget(self.widget)
        self.Setting_widget.setGeometry(QtCore.QRect(10, 50, 831, 481))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Setting_widget.setFont(font)
        self.Setting_widget.setStyleSheet("background-color:rgb(255, 255, 255);")
        self.Setting_widget.setObjectName("Setting_widget")
        self.Show_high_sensitivity = QtWidgets.QWidget(self.Setting_widget)
        self.Show_high_sensitivity.setGeometry(QtCore.QRect(20, 50, 791, 101))
        self.Show_high_sensitivity.setAcceptDrops(False)
        self.Show_high_sensitivity.setAutoFillBackground(False)
        self.Show_high_sensitivity.setObjectName("Show_high_sensitivity")
        self.high_sensitivity_title = QtWidgets.QLabel(self.Show_high_sensitivity)
        self.high_sensitivity_title.setGeometry(QtCore.QRect(20, 10, 411, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(18)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.high_sensitivity_title.setFont(font)
        self.high_sensitivity_title.setStyleSheet("color: rgb(70,70,70);")
        self.high_sensitivity_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.high_sensitivity_title.setObjectName("high_sensitivity_title")
        self.high_sensitivity_illustrate = QtWidgets.QLabel(self.Show_high_sensitivity)
        self.high_sensitivity_illustrate.setGeometry(QtCore.QRect(20, 50, 521, 51))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.high_sensitivity_illustrate.setFont(font)
        self.high_sensitivity_illustrate.setStyleSheet("color: rgb(70,70,70);")
        self.high_sensitivity_illustrate.setScaledContents(False)
        self.high_sensitivity_illustrate.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.high_sensitivity_illustrate.setWordWrap(True)
        self.high_sensitivity_illustrate.setObjectName("high_sensitivity_illustrate")
        self.high_sensitivity_switch_Button = QtWidgets.QPushButton(self.Show_high_sensitivity)
        self.high_sensitivity_switch_Button.setGeometry(QtCore.QRect(660, 30, 91, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.high_sensitivity_switch_Button.sizePolicy().hasHeightForWidth())
        self.high_sensitivity_switch_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.high_sensitivity_switch_Button.setFont(font)
        self.high_sensitivity_switch_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.high_sensitivity_switch_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}")
        self.high_sensitivity_switch_Button.setIconSize(QtCore.QSize(16, 16))
        self.high_sensitivity_switch_Button.setCheckable(False)
        self.high_sensitivity_switch_Button.setObjectName("high_sensitivity_switch_Button")
        self.Setting_Back = QtWidgets.QPushButton(self.Setting_widget)
        self.Setting_Back.setGeometry(QtCore.QRect(20, 10, 101, 41))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Setting_Back.sizePolicy().hasHeightForWidth())
        self.Setting_Back.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Setting_Back.setFont(font)
        self.Setting_Back.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Setting_Back.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    color:rgba(60,60,60,200);\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    color:rgba(60,60,60,255);\n"
"}\n"
"")
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(":/icon/Icon/exit2.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Setting_Back.setIcon(icon1)
        self.Setting_Back.setIconSize(QtCore.QSize(20, 20))
        self.Setting_Back.setCheckable(False)
        self.Setting_Back.setObjectName("Setting_Back")
        self.Llanguage_widget = QtWidgets.QWidget(self.Setting_widget)
        self.Llanguage_widget.setGeometry(QtCore.QRect(20, 270, 791, 101))
        self.Llanguage_widget.setAcceptDrops(False)
        self.Llanguage_widget.setAutoFillBackground(False)
        self.Llanguage_widget.setObjectName("Llanguage_widget")
        self.Language_title = QtWidgets.QLabel(self.Llanguage_widget)
        self.Language_title.setGeometry(QtCore.QRect(20, 10, 321, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(18)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Language_title.setFont(font)
        self.Language_title.setStyleSheet("color: rgb(70,70,70);")
        self.Language_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Language_title.setObjectName("Language_title")
        self.Language_illustrate = QtWidgets.QLabel(self.Llanguage_widget)
        self.Language_illustrate.setGeometry(QtCore.QRect(20, 50, 321, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Language_illustrate.setFont(font)
        self.Language_illustrate.setStyleSheet("color: rgb(70,70,70);")
        self.Language_illustrate.setScaledContents(False)
        self.Language_illustrate.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Language_illustrate.setWordWrap(True)
        self.Language_illustrate.setObjectName("Language_illustrate")
        self.Language_Choose_widget = QtWidgets.QWidget(self.Llanguage_widget)
        self.Language_Choose_widget.setGeometry(QtCore.QRect(350, 0, 441, 101))
        font = QtGui.QFont()
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Language_Choose_widget.setFont(font)
        self.Language_Choose_widget.setObjectName("Language_Choose_widget")
        self.horizontalLayoutWidget = QtWidgets.QWidget(self.Language_Choose_widget)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(0, 10, 431, 81))
        self.horizontalLayoutWidget.setObjectName("horizontalLayoutWidget")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.Language_Traditional_Chinese = QtWidgets.QRadioButton(self.horizontalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Language_Traditional_Chinese.sizePolicy().hasHeightForWidth())
        self.Language_Traditional_Chinese.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Language_Traditional_Chinese.setFont(font)
        self.Language_Traditional_Chinese.setObjectName("Language_Traditional_Chinese")
        self.horizontalLayout.addWidget(self.Language_Traditional_Chinese)
        self.Language_Simplified_Chinese = QtWidgets.QRadioButton(self.horizontalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Language_Simplified_Chinese.sizePolicy().hasHeightForWidth())
        self.Language_Simplified_Chinese.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Language_Simplified_Chinese.setFont(font)
        self.Language_Simplified_Chinese.setObjectName("Language_Simplified_Chinese")
        self.horizontalLayout.addWidget(self.Language_Simplified_Chinese)
        self.Languahe_English = QtWidgets.QRadioButton(self.horizontalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Languahe_English.sizePolicy().hasHeightForWidth())
        self.Languahe_English.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        self.Languahe_English.setFont(font)
        self.Languahe_English.setObjectName("Languahe_English")
        self.horizontalLayout.addWidget(self.Languahe_English)
        self.Theme_widget = QtWidgets.QWidget(self.Setting_widget)
        self.Theme_widget.setGeometry(QtCore.QRect(20, 160, 791, 101))
        self.Theme_widget.setObjectName("Theme_widget")
        self.Theme_title = QtWidgets.QLabel(self.Theme_widget)
        self.Theme_title.setGeometry(QtCore.QRect(20, 10, 351, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(18)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Theme_title.setFont(font)
        self.Theme_title.setStyleSheet("color: rgb(70,70,70);")
        self.Theme_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Theme_title.setObjectName("Theme_title")
        self.Theme_illustrate = QtWidgets.QLabel(self.Theme_widget)
        self.Theme_illustrate.setGeometry(QtCore.QRect(20, 50, 351, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Theme_illustrate.setFont(font)
        self.Theme_illustrate.setStyleSheet("color: rgb(70,70,70);")
        self.Theme_illustrate.setScaledContents(False)
        self.Theme_illustrate.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Theme_illustrate.setWordWrap(True)
        self.Theme_illustrate.setObjectName("Theme_illustrate")
        self.Language_Choose_widget_2 = QtWidgets.QWidget(self.Theme_widget)
        self.Language_Choose_widget_2.setGeometry(QtCore.QRect(390, 0, 401, 101))
        font = QtGui.QFont()
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Language_Choose_widget_2.setFont(font)
        self.Language_Choose_widget_2.setObjectName("Language_Choose_widget_2")
        self.gridLayoutWidget = QtWidgets.QWidget(self.Language_Choose_widget_2)
        self.gridLayoutWidget.setGeometry(QtCore.QRect(0, 10, 391, 80))
        self.gridLayoutWidget.setObjectName("gridLayoutWidget")
        self.gridLayout = QtWidgets.QGridLayout(self.gridLayoutWidget)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.gridLayout.setObjectName("gridLayout")
        self.Theme_Black = QtWidgets.QRadioButton(self.gridLayoutWidget)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Theme_Black.setFont(font)
        self.Theme_Black.setObjectName("Theme_Black")
        self.gridLayout.addWidget(self.Theme_Black, 1, 1, 1, 1)
        self.Theme_White = QtWidgets.QRadioButton(self.gridLayoutWidget)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Theme_White.setFont(font)
        self.Theme_White.setObjectName("Theme_White")
        self.gridLayout.addWidget(self.Theme_White, 1, 0, 1, 1)
        self.Theme_Pink = QtWidgets.QRadioButton(self.gridLayoutWidget)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Theme_Pink.setFont(font)
        self.Theme_Pink.setObjectName("Theme_Pink")
        self.gridLayout.addWidget(self.Theme_Pink, 1, 2, 1, 1)
        self.Theme_Blue = QtWidgets.QRadioButton(self.gridLayoutWidget)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        self.Theme_Blue.setFont(font)
        self.Theme_Blue.setObjectName("Theme_Blue")
        self.gridLayout.addWidget(self.Theme_Blue, 2, 0, 1, 1)
        self.Theme_Red = QtWidgets.QRadioButton(self.gridLayoutWidget)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Theme_Red.setFont(font)
        self.Theme_Red.setObjectName("Theme_Red")
        self.gridLayout.addWidget(self.Theme_Red, 2, 1, 1, 1)
        self.Theme_Green = QtWidgets.QRadioButton(self.gridLayoutWidget)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Theme_Green.setFont(font)
        self.Theme_Green.setObjectName("Theme_Green")
        self.gridLayout.addWidget(self.Theme_Green, 2, 2, 1, 1)
        self.More_Tools_widget = QtWidgets.QWidget(self.widget)
        self.More_Tools_widget.setGeometry(QtCore.QRect(170, 50, 671, 481))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.More_Tools_widget.setFont(font)
        self.More_Tools_widget.setStyleSheet("background-color:rgba(255, 255, 255,240);")
        self.More_Tools_widget.setObjectName("More_Tools_widget")
        self.More_Tools_Back = QtWidgets.QPushButton(self.More_Tools_widget)
        self.More_Tools_Back.setGeometry(QtCore.QRect(10, 10, 101, 41))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.More_Tools_Back.sizePolicy().hasHeightForWidth())
        self.More_Tools_Back.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.More_Tools_Back.setFont(font)
        self.More_Tools_Back.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.More_Tools_Back.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    color:rgba(60,60,60,200);\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    color:rgba(60,60,60,255);\n"
"}\n"
"")
        self.More_Tools_Back.setIcon(icon1)
        self.More_Tools_Back.setIconSize(QtCore.QSize(20, 20))
        self.More_Tools_Back.setCheckable(False)
        self.More_Tools_Back.setObjectName("More_Tools_Back")
        self.verticalLayoutWidget_7 = QtWidgets.QWidget(self.More_Tools_widget)
        self.verticalLayoutWidget_7.setGeometry(QtCore.QRect(19, 59, 631, 401))
        self.verticalLayoutWidget_7.setObjectName("verticalLayoutWidget_7")
        self.More_Tools_verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_7)
        self.More_Tools_verticalLayout.setContentsMargins(10, 10, 10, 10)
        self.More_Tools_verticalLayout.setSpacing(5)
        self.More_Tools_verticalLayout.setObjectName("More_Tools_verticalLayout")
        self.Look_for_File_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_7)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Look_for_File_Button.sizePolicy().hasHeightForWidth())
        self.Look_for_File_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Look_for_File_Button.setFont(font)
        self.Look_for_File_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Look_for_File_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.Look_for_File_Button.setIconSize(QtCore.QSize(16, 16))
        self.Look_for_File_Button.setCheckable(False)
        self.Look_for_File_Button.setObjectName("Look_for_File_Button")
        self.More_Tools_verticalLayout.addWidget(self.Look_for_File_Button)
        self.Encryption_Text_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_7)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Encryption_Text_Button.sizePolicy().hasHeightForWidth())
        self.Encryption_Text_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Encryption_Text_Button.setFont(font)
        self.Encryption_Text_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Encryption_Text_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.Encryption_Text_Button.setIconSize(QtCore.QSize(16, 16))
        self.Encryption_Text_Button.setCheckable(False)
        self.Encryption_Text_Button.setObjectName("Encryption_Text_Button")
        self.More_Tools_verticalLayout.addWidget(self.Encryption_Text_Button)
        self.Change_Users_Password_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_7)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Change_Users_Password_Button.sizePolicy().hasHeightForWidth())
        self.Change_Users_Password_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Change_Users_Password_Button.setFont(font)
        self.Change_Users_Password_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Change_Users_Password_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.Change_Users_Password_Button.setIconSize(QtCore.QSize(16, 16))
        self.Change_Users_Password_Button.setCheckable(False)
        self.Change_Users_Password_Button.setObjectName("Change_Users_Password_Button")
        self.More_Tools_verticalLayout.addWidget(self.Change_Users_Password_Button)
        self.Internet_location_Query_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_7)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Internet_location_Query_Button.sizePolicy().hasHeightForWidth())
        self.Internet_location_Query_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Internet_location_Query_Button.setFont(font)
        self.Internet_location_Query_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Internet_location_Query_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.Internet_location_Query_Button.setIconSize(QtCore.QSize(16, 16))
        self.Internet_location_Query_Button.setCheckable(False)
        self.Internet_location_Query_Button.setObjectName("Internet_location_Query_Button")
        self.More_Tools_verticalLayout.addWidget(self.Internet_location_Query_Button)
        self.Rework_Network_Configuration_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_7)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Rework_Network_Configuration_Button.sizePolicy().hasHeightForWidth())
        self.Rework_Network_Configuration_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Rework_Network_Configuration_Button.setFont(font)
        self.Rework_Network_Configuration_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Rework_Network_Configuration_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.Rework_Network_Configuration_Button.setIconSize(QtCore.QSize(16, 16))
        self.Rework_Network_Configuration_Button.setCheckable(False)
        self.Rework_Network_Configuration_Button.setObjectName("Rework_Network_Configuration_Button")
        self.More_Tools_verticalLayout.addWidget(self.Rework_Network_Configuration_Button)
        self.Encryption_Text_widget = QtWidgets.QWidget(self.widget)
        self.Encryption_Text_widget.setGeometry(QtCore.QRect(170, 50, 671, 481))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Encryption_Text_widget.setFont(font)
        self.Encryption_Text_widget.setStyleSheet("background-color:rgba(255, 255, 255,240);")
        self.Encryption_Text_widget.setObjectName("Encryption_Text_widget")
        self.Encryption_Text_Back = QtWidgets.QPushButton(self.Encryption_Text_widget)
        self.Encryption_Text_Back.setGeometry(QtCore.QRect(10, 10, 101, 41))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Encryption_Text_Back.sizePolicy().hasHeightForWidth())
        self.Encryption_Text_Back.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Encryption_Text_Back.setFont(font)
        self.Encryption_Text_Back.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Encryption_Text_Back.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    color:rgba(60,60,60,200);\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    color:rgba(60,60,60,255);\n"
"}\n"
"")
        self.Encryption_Text_Back.setIcon(icon1)
        self.Encryption_Text_Back.setIconSize(QtCore.QSize(20, 20))
        self.Encryption_Text_Back.setCheckable(False)
        self.Encryption_Text_Back.setObjectName("Encryption_Text_Back")
        self.Encryption_Text_Run_Button = QtWidgets.QPushButton(self.Encryption_Text_widget)
        self.Encryption_Text_Run_Button.setGeometry(QtCore.QRect(430, 400, 101, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Encryption_Text_Run_Button.sizePolicy().hasHeightForWidth())
        self.Encryption_Text_Run_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Encryption_Text_Run_Button.setFont(font)
        self.Encryption_Text_Run_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Encryption_Text_Run_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.Encryption_Text_Run_Button.setIconSize(QtCore.QSize(16, 16))
        self.Encryption_Text_Run_Button.setCheckable(False)
        self.Encryption_Text_Run_Button.setObjectName("Encryption_Text_Run_Button")
        self.Encryption_Text_input = QtWidgets.QTextEdit(self.Encryption_Text_widget)
        self.Encryption_Text_input.setGeometry(QtCore.QRect(30, 100, 301, 291))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Encryption_Text_input.setFont(font)
        self.Encryption_Text_input.setObjectName("Encryption_Text_input")
        self.Encryption_Text_output = QtWidgets.QTextEdit(self.Encryption_Text_widget)
        self.Encryption_Text_output.setGeometry(QtCore.QRect(340, 100, 301, 291))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Encryption_Text_output.setFont(font)
        self.Encryption_Text_output.setObjectName("Encryption_Text_output")
        self.Encryption_Text_Password_input = QtWidgets.QLineEdit(self.Encryption_Text_widget)
        self.Encryption_Text_Password_input.setGeometry(QtCore.QRect(150, 400, 271, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Encryption_Text_Password_input.setFont(font)
        self.Encryption_Text_Password_input.setObjectName("Encryption_Text_Password_input")
        self.Encryption_Text_title2 = QtWidgets.QLabel(self.Encryption_Text_widget)
        self.Encryption_Text_title2.setGeometry(QtCore.QRect(340, 60, 301, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.Encryption_Text_title2.setFont(font)
        self.Encryption_Text_title2.setStyleSheet("")
        self.Encryption_Text_title2.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Encryption_Text_title2.setObjectName("Encryption_Text_title2")
        self.Encryption_Text_Password_title = QtWidgets.QLabel(self.Encryption_Text_widget)
        self.Encryption_Text_Password_title.setGeometry(QtCore.QRect(30, 400, 111, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.Encryption_Text_Password_title.setFont(font)
        self.Encryption_Text_Password_title.setStyleSheet("")
        self.Encryption_Text_Password_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Encryption_Text_Password_title.setObjectName("Encryption_Text_Password_title")
        self.Encryption_Text_title = QtWidgets.QLabel(self.Encryption_Text_widget)
        self.Encryption_Text_title.setGeometry(QtCore.QRect(30, 60, 301, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.Encryption_Text_title.setFont(font)
        self.Encryption_Text_title.setStyleSheet("")
        self.Encryption_Text_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Encryption_Text_title.setObjectName("Encryption_Text_title")
        self.Decrypt_Text_Run_Button = QtWidgets.QPushButton(self.Encryption_Text_widget)
        self.Decrypt_Text_Run_Button.setGeometry(QtCore.QRect(540, 400, 101, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Decrypt_Text_Run_Button.sizePolicy().hasHeightForWidth())
        self.Decrypt_Text_Run_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Decrypt_Text_Run_Button.setFont(font)
        self.Decrypt_Text_Run_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Decrypt_Text_Run_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.Decrypt_Text_Run_Button.setIconSize(QtCore.QSize(16, 16))
        self.Decrypt_Text_Run_Button.setCheckable(False)
        self.Decrypt_Text_Run_Button.setObjectName("Decrypt_Text_Run_Button")
        self.Protection_widget = QtWidgets.QWidget(self.widget)
        self.Protection_widget.setGeometry(QtCore.QRect(170, 50, 671, 481))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Protection_widget.setFont(font)
        self.Protection_widget.setStyleSheet("background-color:rgba(255, 255, 255,240);")
        self.Protection_widget.setObjectName("Protection_widget")
        self.Real_time_Protection_widget = QtWidgets.QWidget(self.Protection_widget)
        self.Real_time_Protection_widget.setGeometry(QtCore.QRect(20, 30, 631, 111))
        self.Real_time_Protection_widget.setAcceptDrops(False)
        self.Real_time_Protection_widget.setLayoutDirection(QtCore.Qt.RightToLeft)
        self.Real_time_Protection_widget.setAutoFillBackground(False)
        self.Real_time_Protection_widget.setObjectName("Real_time_Protection_widget")
        self.Protection_title = QtWidgets.QLabel(self.Real_time_Protection_widget)
        self.Protection_title.setGeometry(QtCore.QRect(30, 10, 341, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(18)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Protection_title.setFont(font)
        self.Protection_title.setStyleSheet("color: rgb(70,70,70);")
        self.Protection_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Protection_title.setObjectName("Protection_title")
        self.Protection_illustrate = QtWidgets.QLabel(self.Real_time_Protection_widget)
        self.Protection_illustrate.setGeometry(QtCore.QRect(30, 50, 421, 51))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Protection_illustrate.setFont(font)
        self.Protection_illustrate.setStyleSheet("color: rgb(70,70,70);")
        self.Protection_illustrate.setScaledContents(False)
        self.Protection_illustrate.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Protection_illustrate.setWordWrap(True)
        self.Protection_illustrate.setObjectName("Protection_illustrate")
        self.Protection_switch_Button = QtWidgets.QPushButton(self.Real_time_Protection_widget)
        self.Protection_switch_Button.setGeometry(QtCore.QRect(500, 35, 91, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Protection_switch_Button.sizePolicy().hasHeightForWidth())
        self.Protection_switch_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Protection_switch_Button.setFont(font)
        self.Protection_switch_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Protection_switch_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}")
        self.Protection_switch_Button.setIconSize(QtCore.QSize(16, 16))
        self.Protection_switch_Button.setCheckable(False)
        self.Protection_switch_Button.setObjectName("Protection_switch_Button")
        self.Navigation_Bar = QtWidgets.QWidget(self.widget)
        self.Navigation_Bar.setGeometry(QtCore.QRect(10, 50, 161, 481))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Navigation_Bar.setFont(font)
        self.Navigation_Bar.setStyleSheet("QWidget#Navigation_Bar\n"
"{\n"
"    background-color:rgb(230, 230, 230);\n"
"    border-top-right-radius:2px;\n"
"    border-bottom-right-radius:2px;\n"
"}\n"
"\n"
"")
        self.Navigation_Bar.setObjectName("Navigation_Bar")
        self.verticalLayoutWidget = QtWidgets.QWidget(self.Navigation_Bar)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(0, 0, 161, 481))
        self.verticalLayoutWidget.setObjectName("verticalLayoutWidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setContentsMargins(10, 10, 0, 10)
        self.verticalLayout.setSpacing(30)
        self.verticalLayout.setObjectName("verticalLayout")
        self.State_Button = QtWidgets.QPushButton(self.verticalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.State_Button.sizePolicy().hasHeightForWidth())
        self.State_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(15)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.State_Button.setFont(font)
        self.State_Button.setCursor(QtGui.QCursor(QtCore.Qt.ArrowCursor))
        self.State_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.State_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    border-top-left-radius:15px;\n"
"    border-bottom-left-radius:15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(255, 255, 255,70);\n"
"    color:rgba(0,0,0,170);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(255, 255, 255,110);\n"
"}")
        self.State_Button.setIconSize(QtCore.QSize(16, 16))
        self.State_Button.setCheckable(False)
        self.State_Button.setObjectName("State_Button")
        self.verticalLayout.addWidget(self.State_Button)
        self.Virus_Scan_Button = QtWidgets.QPushButton(self.verticalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Virus_Scan_Button.sizePolicy().hasHeightForWidth())
        self.Virus_Scan_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(15)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Virus_Scan_Button.setFont(font)
        self.Virus_Scan_Button.setCursor(QtGui.QCursor(QtCore.Qt.ArrowCursor))
        self.Virus_Scan_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Virus_Scan_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    border-top-left-radius:15px;\n"
"    border-bottom-left-radius:15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(255, 255, 255,70);\n"
"    color:rgba(0,0,0,170);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(255, 255, 255,110);\n"
"}")
        self.Virus_Scan_Button.setIconSize(QtCore.QSize(16, 16))
        self.Virus_Scan_Button.setCheckable(False)
        self.Virus_Scan_Button.setObjectName("Virus_Scan_Button")
        self.verticalLayout.addWidget(self.Virus_Scan_Button)
        self.Tools_Button = QtWidgets.QPushButton(self.verticalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Tools_Button.sizePolicy().hasHeightForWidth())
        self.Tools_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(15)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Tools_Button.setFont(font)
        self.Tools_Button.setCursor(QtGui.QCursor(QtCore.Qt.ArrowCursor))
        self.Tools_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Tools_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    border-top-left-radius:15px;\n"
"    border-bottom-left-radius:15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(255, 255, 255,70);\n"
"    color:rgba(0,0,0,170);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(255, 255, 255,110);\n"
"}")
        self.Tools_Button.setIconSize(QtCore.QSize(16, 16))
        self.Tools_Button.setCheckable(False)
        self.Tools_Button.setObjectName("Tools_Button")
        self.verticalLayout.addWidget(self.Tools_Button)
        self.Protection_Button = QtWidgets.QPushButton(self.verticalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Protection_Button.sizePolicy().hasHeightForWidth())
        self.Protection_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(15)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Protection_Button.setFont(font)
        self.Protection_Button.setCursor(QtGui.QCursor(QtCore.Qt.ArrowCursor))
        self.Protection_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Protection_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    border-top-left-radius:15px;\n"
"    border-bottom-left-radius:15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(255, 255, 255,70);\n"
"    color:rgba(0,0,0,170);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(255, 255, 255,110);\n"
"}")
        self.Protection_Button.setIconSize(QtCore.QSize(16, 16))
        self.Protection_Button.setCheckable(False)
        self.Protection_Button.setObjectName("Protection_Button")
        self.verticalLayout.addWidget(self.Protection_Button)
        self.label = QtWidgets.QPushButton(self.Navigation_Bar)
        self.label.setEnabled(False)
        self.label.setGeometry(QtCore.QRect(25, 35, 5, 40))
        self.label.setMouseTracking(False)
        self.label.setAutoFillBackground(False)
        self.label.setStyleSheet("QPushButton#label\n"
"{\n"
"    background-color:rgba(255,255,255,255);\n"
"    border-radius: 2px;\n"
"}")
        self.label.setText("")
        self.label.setCheckable(False)
        self.label.setAutoDefault(False)
        self.label.setDefault(True)
        self.label.setFlat(False)
        self.label.setObjectName("label")
        self.Virus_Scan_widget = QtWidgets.QWidget(self.widget)
        self.Virus_Scan_widget.setGeometry(QtCore.QRect(170, 50, 671, 481))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Virus_Scan_widget.setFont(font)
        self.Virus_Scan_widget.setStyleSheet("background-color:rgba(255, 255, 255,240);")
        self.Virus_Scan_widget.setObjectName("Virus_Scan_widget")
        self.Virus_Scan_title = QtWidgets.QLabel(self.Virus_Scan_widget)
        self.Virus_Scan_title.setGeometry(QtCore.QRect(45, 40, 281, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(18)
        self.Virus_Scan_title.setFont(font)
        self.Virus_Scan_title.setStyleSheet("color: rgb(70,70,70);")
        self.Virus_Scan_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Virus_Scan_title.setObjectName("Virus_Scan_title")
        self.Virus_Scan_text = QtWidgets.QLabel(self.Virus_Scan_widget)
        self.Virus_Scan_text.setGeometry(QtCore.QRect(45, 90, 581, 61))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        self.Virus_Scan_text.setFont(font)
        self.Virus_Scan_text.setStyleSheet("color: rgb(70,70,70);")
        self.Virus_Scan_text.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Virus_Scan_text.setWordWrap(True)
        self.Virus_Scan_text.setObjectName("Virus_Scan_text")
        self.Virus_Scan_choose_Button = QtWidgets.QPushButton(self.Virus_Scan_widget)
        self.Virus_Scan_choose_Button.setGeometry(QtCore.QRect(480, 45, 141, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Virus_Scan_choose_Button.sizePolicy().hasHeightForWidth())
        self.Virus_Scan_choose_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Virus_Scan_choose_Button.setFont(font)
        self.Virus_Scan_choose_Button.setMouseTracking(False)
        self.Virus_Scan_choose_Button.setTabletTracking(False)
        self.Virus_Scan_choose_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Virus_Scan_choose_Button.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.Virus_Scan_choose_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(100,200,100,200);\n"
"    border-radius: 3px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(100,220,100,200);\n"
"}")
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(":/icon/Icon/multimedia.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Virus_Scan_choose_Button.setIcon(icon2)
        self.Virus_Scan_choose_Button.setIconSize(QtCore.QSize(10, 10))
        self.Virus_Scan_choose_Button.setCheckable(False)
        self.Virus_Scan_choose_Button.setAutoRepeat(False)
        self.Virus_Scan_choose_Button.setAutoExclusive(False)
        self.Virus_Scan_choose_Button.setAutoRepeatDelay(300)
        self.Virus_Scan_choose_Button.setAutoRepeatInterval(100)
        self.Virus_Scan_choose_Button.setDefault(False)
        self.Virus_Scan_choose_Button.setFlat(False)
        self.Virus_Scan_choose_Button.setObjectName("Virus_Scan_choose_Button")
        self.Virus_Scan_output = QtWidgets.QListView(self.Virus_Scan_widget)
        self.Virus_Scan_output.setEnabled(True)
        self.Virus_Scan_output.setGeometry(QtCore.QRect(45, 160, 581, 291))
        self.Virus_Scan_output.setStyleSheet("QWidget::item\n"
"{\n"
"background-color: rgba(50,50,50,30);\n"
"color:black;\n"
"border: transparent;\n"
"border-bottom: 1px solid #dbdbdb;\n"
"padding: 5px;\n"
"}\n"
"QWidget::item:hover\n"
"{\n"
"background-color: rgba(50,50,50,40);\n"
"}\n"
"QListView\n"
"{\n"
"outline: none;\n"
"}")
        self.Virus_Scan_output.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.Virus_Scan_output.setObjectName("Virus_Scan_output")
        self.Virus_Scan_choose_widget = QtWidgets.QWidget(self.Virus_Scan_widget)
        self.Virus_Scan_choose_widget.setGeometry(QtCore.QRect(480, 82, 141, 0))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Virus_Scan_choose_widget.sizePolicy().hasHeightForWidth())
        self.Virus_Scan_choose_widget.setSizePolicy(sizePolicy)
        self.Virus_Scan_choose_widget.setStyleSheet("background-color:rgba(200, 200, 200,200);")
        self.Virus_Scan_choose_widget.setObjectName("Virus_Scan_choose_widget")
        self.verticalLayoutWidget_3 = QtWidgets.QWidget(self.Virus_Scan_choose_widget)
        self.verticalLayoutWidget_3.setGeometry(QtCore.QRect(0, 0, 151, 101))
        self.verticalLayoutWidget_3.setObjectName("verticalLayoutWidget_3")
        self.Virus_Scan_choose_verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_3)
        self.Virus_Scan_choose_verticalLayout.setSizeConstraint(QtWidgets.QLayout.SetDefaultConstraint)
        self.Virus_Scan_choose_verticalLayout.setContentsMargins(1, 0, 1, 0)
        self.Virus_Scan_choose_verticalLayout.setSpacing(3)
        self.Virus_Scan_choose_verticalLayout.setObjectName("Virus_Scan_choose_verticalLayout")
        self.File_Scan_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_3)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.File_Scan_Button.sizePolicy().hasHeightForWidth())
        self.File_Scan_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.File_Scan_Button.setFont(font)
        self.File_Scan_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.File_Scan_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    border-radius: 5px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(50, 50, 50,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(50, 50, 50,90);\n"
"}")
        self.File_Scan_Button.setIconSize(QtCore.QSize(16, 16))
        self.File_Scan_Button.setCheckable(False)
        self.File_Scan_Button.setObjectName("File_Scan_Button")
        self.Virus_Scan_choose_verticalLayout.addWidget(self.File_Scan_Button)
        self.Path_Scan_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_3)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Path_Scan_Button.sizePolicy().hasHeightForWidth())
        self.Path_Scan_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Path_Scan_Button.setFont(font)
        self.Path_Scan_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Path_Scan_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    border-radius: 5px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(50, 50, 50,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(50, 50, 50,90);\n"
"}")
        self.Path_Scan_Button.setIconSize(QtCore.QSize(16, 16))
        self.Path_Scan_Button.setCheckable(False)
        self.Path_Scan_Button.setObjectName("Path_Scan_Button")
        self.Virus_Scan_choose_verticalLayout.addWidget(self.Path_Scan_Button)
        self.Disk_Scan_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_3)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Disk_Scan_Button.sizePolicy().hasHeightForWidth())
        self.Disk_Scan_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Disk_Scan_Button.setFont(font)
        self.Disk_Scan_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Disk_Scan_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    border-radius: 5px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(50, 50, 50,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(50, 50, 50,90);\n"
"}")
        self.Disk_Scan_Button.setIconSize(QtCore.QSize(16, 16))
        self.Disk_Scan_Button.setCheckable(False)
        self.Disk_Scan_Button.setObjectName("Disk_Scan_Button")
        self.Virus_Scan_choose_verticalLayout.addWidget(self.Disk_Scan_Button)
        self.Virus_Scan_Solve_Button = QtWidgets.QPushButton(self.Virus_Scan_widget)
        self.Virus_Scan_Solve_Button.setGeometry(QtCore.QRect(330, 45, 141, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Virus_Scan_Solve_Button.sizePolicy().hasHeightForWidth())
        self.Virus_Scan_Solve_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Virus_Scan_Solve_Button.setFont(font)
        self.Virus_Scan_Solve_Button.setMouseTracking(False)
        self.Virus_Scan_Solve_Button.setTabletTracking(False)
        self.Virus_Scan_Solve_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Virus_Scan_Solve_Button.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.Virus_Scan_Solve_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(230,70,70,200);\n"
"    border-radius: 3px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(255,70,70,200);\n"
"}")
        self.Virus_Scan_Solve_Button.setIconSize(QtCore.QSize(10, 10))
        self.Virus_Scan_Solve_Button.setCheckable(False)
        self.Virus_Scan_Solve_Button.setAutoRepeat(False)
        self.Virus_Scan_Solve_Button.setAutoExclusive(False)
        self.Virus_Scan_Solve_Button.setAutoRepeatDelay(300)
        self.Virus_Scan_Solve_Button.setAutoRepeatInterval(100)
        self.Virus_Scan_Solve_Button.setDefault(False)
        self.Virus_Scan_Solve_Button.setFlat(False)
        self.Virus_Scan_Solve_Button.setObjectName("Virus_Scan_Solve_Button")
        self.Virus_Scan_Break_Button = QtWidgets.QPushButton(self.Virus_Scan_widget)
        self.Virus_Scan_Break_Button.setGeometry(QtCore.QRect(480, 45, 141, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Virus_Scan_Break_Button.sizePolicy().hasHeightForWidth())
        self.Virus_Scan_Break_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Virus_Scan_Break_Button.setFont(font)
        self.Virus_Scan_Break_Button.setMouseTracking(False)
        self.Virus_Scan_Break_Button.setTabletTracking(False)
        self.Virus_Scan_Break_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Virus_Scan_Break_Button.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.Virus_Scan_Break_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(230,70,70,200);\n"
"    border-radius: 3px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(255,70,70,200);\n"
"}")
        self.Virus_Scan_Break_Button.setIconSize(QtCore.QSize(10, 10))
        self.Virus_Scan_Break_Button.setCheckable(False)
        self.Virus_Scan_Break_Button.setAutoRepeat(False)
        self.Virus_Scan_Break_Button.setAutoExclusive(False)
        self.Virus_Scan_Break_Button.setAutoRepeatDelay(300)
        self.Virus_Scan_Break_Button.setAutoRepeatInterval(100)
        self.Virus_Scan_Break_Button.setDefault(False)
        self.Virus_Scan_Break_Button.setFlat(False)
        self.Virus_Scan_Break_Button.setObjectName("Virus_Scan_Break_Button")
        self.Virus_Scan_ProgressBar = QtWidgets.QProgressBar(self.Virus_Scan_widget)
        self.Virus_Scan_ProgressBar.setGeometry(QtCore.QRect(45, 137, 581, 21))
        self.Virus_Scan_ProgressBar.setProperty("value", 0)
        self.Virus_Scan_ProgressBar.setTextVisible(False)
        self.Virus_Scan_ProgressBar.setObjectName("Virus_Scan_ProgressBar")
        self.State_widget = QtWidgets.QWidget(self.widget)
        self.State_widget.setGeometry(QtCore.QRect(170, 49, 671, 481))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.State_widget.setFont(font)
        self.State_widget.setStyleSheet("background-color:rgb(255, 255, 255);")
        self.State_widget.setObjectName("State_widget")
        self.State_title = QtWidgets.QLabel(self.State_widget)
        self.State_title.setGeometry(QtCore.QRect(34, 230, 601, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(14)
        font.setBold(True)
        font.setWeight(75)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.State_title.setFont(font)
        self.State_title.setStyleSheet("")
        self.State_title.setAlignment(QtCore.Qt.AlignCenter)
        self.State_title.setObjectName("State_title")
        self.State_icon = QtWidgets.QLabel(self.State_widget)
        self.State_icon.setGeometry(QtCore.QRect(255, 70, 161, 151))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(1)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.State_icon.setFont(font)
        self.State_icon.setText("")
        self.State_icon.setPixmap(QtGui.QPixmap(":/icon/Icon/check.png"))
        self.State_icon.setScaledContents(True)
        self.State_icon.setObjectName("State_icon")
        self.State_output = QtWidgets.QTextEdit(self.State_widget)
        self.State_output.setGeometry(QtCore.QRect(95, 320, 481, 131))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        font.setStrikeOut(False)
        font.setKerning(True)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.State_output.setFont(font)
        self.State_output.setUndoRedoEnabled(True)
        self.State_output.setTextInteractionFlags(QtCore.Qt.TextSelectableByKeyboard|QtCore.Qt.TextSelectableByMouse)
        self.State_output.setObjectName("State_output")
        self.State_log = QtWidgets.QLabel(self.State_widget)
        self.State_log.setGeometry(QtCore.QRect(95, 280, 481, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setBold(False)
        font.setWeight(50)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.State_log.setFont(font)
        self.State_log.setStyleSheet("")
        self.State_log.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.State_log.setObjectName("State_log")
        self.Change_Users_Password_widget = QtWidgets.QWidget(self.widget)
        self.Change_Users_Password_widget.setGeometry(QtCore.QRect(170, 50, 671, 481))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Change_Users_Password_widget.setFont(font)
        self.Change_Users_Password_widget.setStyleSheet("background-color:rgba(255, 255, 255,240);")
        self.Change_Users_Password_widget.setObjectName("Change_Users_Password_widget")
        self.Change_Users_Password_Back = QtWidgets.QPushButton(self.Change_Users_Password_widget)
        self.Change_Users_Password_Back.setGeometry(QtCore.QRect(10, 10, 101, 41))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Change_Users_Password_Back.sizePolicy().hasHeightForWidth())
        self.Change_Users_Password_Back.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Change_Users_Password_Back.setFont(font)
        self.Change_Users_Password_Back.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Change_Users_Password_Back.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    color:rgba(60,60,60,200);\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    color:rgba(60,60,60,255);\n"
"}\n"
"")
        self.Change_Users_Password_Back.setIcon(icon1)
        self.Change_Users_Password_Back.setIconSize(QtCore.QSize(20, 20))
        self.Change_Users_Password_Back.setCheckable(False)
        self.Change_Users_Password_Back.setObjectName("Change_Users_Password_Back")
        self.Change_Users_Password_New_Password_input = QtWidgets.QLineEdit(self.Change_Users_Password_widget)
        self.Change_Users_Password_New_Password_input.setGeometry(QtCore.QRect(30, 200, 481, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        self.Change_Users_Password_New_Password_input.setFont(font)
        self.Change_Users_Password_New_Password_input.setObjectName("Change_Users_Password_New_Password_input")
        self.Change_Users_Password_New_Password_title = QtWidgets.QLabel(self.Change_Users_Password_widget)
        self.Change_Users_Password_New_Password_title.setGeometry(QtCore.QRect(30, 160, 471, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.Change_Users_Password_New_Password_title.setFont(font)
        self.Change_Users_Password_New_Password_title.setStyleSheet("")
        self.Change_Users_Password_New_Password_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Change_Users_Password_New_Password_title.setObjectName("Change_Users_Password_New_Password_title")
        self.Change_Users_Password_User_Name_title = QtWidgets.QLabel(self.Change_Users_Password_widget)
        self.Change_Users_Password_User_Name_title.setGeometry(QtCore.QRect(30, 80, 471, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.Change_Users_Password_User_Name_title.setFont(font)
        self.Change_Users_Password_User_Name_title.setStyleSheet("")
        self.Change_Users_Password_User_Name_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Change_Users_Password_User_Name_title.setObjectName("Change_Users_Password_User_Name_title")
        self.Change_Users_Password_User_Name_input = QtWidgets.QLineEdit(self.Change_Users_Password_widget)
        self.Change_Users_Password_User_Name_input.setGeometry(QtCore.QRect(30, 120, 481, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        self.Change_Users_Password_User_Name_input.setFont(font)
        self.Change_Users_Password_User_Name_input.setObjectName("Change_Users_Password_User_Name_input")
        self.Change_Users_Password_Run_Button = QtWidgets.QPushButton(self.Change_Users_Password_widget)
        self.Change_Users_Password_Run_Button.setGeometry(QtCore.QRect(530, 160, 101, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Change_Users_Password_Run_Button.sizePolicy().hasHeightForWidth())
        self.Change_Users_Password_Run_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Change_Users_Password_Run_Button.setFont(font)
        self.Change_Users_Password_Run_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Change_Users_Password_Run_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.Change_Users_Password_Run_Button.setIconSize(QtCore.QSize(16, 16))
        self.Change_Users_Password_Run_Button.setCheckable(False)
        self.Change_Users_Password_Run_Button.setObjectName("Change_Users_Password_Run_Button")
        self.System_Info_widget = QtWidgets.QWidget(self.widget)
        self.System_Info_widget.setGeometry(QtCore.QRect(170, 50, 671, 481))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.System_Info_widget.setFont(font)
        self.System_Info_widget.setStyleSheet("background-color:rgba(255, 255, 255,240);")
        self.System_Info_widget.setObjectName("System_Info_widget")
        self.System_Info_Back = QtWidgets.QPushButton(self.System_Info_widget)
        self.System_Info_Back.setGeometry(QtCore.QRect(10, 10, 101, 41))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.System_Info_Back.sizePolicy().hasHeightForWidth())
        self.System_Info_Back.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.System_Info_Back.setFont(font)
        self.System_Info_Back.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.System_Info_Back.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    color:rgba(60,60,60,200);\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    color:rgba(60,60,60,255);\n"
"}\n"
"")
        self.System_Info_Back.setIcon(icon1)
        self.System_Info_Back.setIconSize(QtCore.QSize(20, 20))
        self.System_Info_Back.setCheckable(False)
        self.System_Info_Back.setObjectName("System_Info_Back")
        self.System_Info_View = QtWidgets.QTextEdit(self.System_Info_widget)
        self.System_Info_View.setGeometry(QtCore.QRect(30, 60, 611, 391))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.System_Info_View.setFont(font)
        self.System_Info_View.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        self.System_Info_View.setObjectName("System_Info_View")
        self.Develop_Tools_widget = QtWidgets.QWidget(self.widget)
        self.Develop_Tools_widget.setGeometry(QtCore.QRect(170, 50, 671, 481))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Develop_Tools_widget.setFont(font)
        self.Develop_Tools_widget.setStyleSheet("background-color:rgba(255, 255, 255,240);")
        self.Develop_Tools_widget.setObjectName("Develop_Tools_widget")
        self.Develop_Tools_Back = QtWidgets.QPushButton(self.Develop_Tools_widget)
        self.Develop_Tools_Back.setGeometry(QtCore.QRect(10, 10, 101, 41))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Develop_Tools_Back.sizePolicy().hasHeightForWidth())
        self.Develop_Tools_Back.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Develop_Tools_Back.setFont(font)
        self.Develop_Tools_Back.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Develop_Tools_Back.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    color:rgba(60,60,60,200);\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    color:rgba(60,60,60,255);\n"
"}\n"
"")
        self.Develop_Tools_Back.setIcon(icon1)
        self.Develop_Tools_Back.setIconSize(QtCore.QSize(20, 20))
        self.Develop_Tools_Back.setCheckable(False)
        self.Develop_Tools_Back.setObjectName("Develop_Tools_Back")
        self.verticalLayoutWidget_6 = QtWidgets.QWidget(self.Develop_Tools_widget)
        self.verticalLayoutWidget_6.setGeometry(QtCore.QRect(20, 60, 631, 401))
        self.verticalLayoutWidget_6.setObjectName("verticalLayoutWidget_6")
        self.Develop_verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_6)
        self.Develop_verticalLayout.setContentsMargins(10, 10, 10, 10)
        self.Develop_verticalLayout.setSpacing(5)
        self.Develop_verticalLayout.setObjectName("Develop_verticalLayout")
        self.Customize_REG_Command_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_6)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Customize_REG_Command_Button.sizePolicy().hasHeightForWidth())
        self.Customize_REG_Command_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Customize_REG_Command_Button.setFont(font)
        self.Customize_REG_Command_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Customize_REG_Command_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.Customize_REG_Command_Button.setIconSize(QtCore.QSize(16, 16))
        self.Customize_REG_Command_Button.setCheckable(False)
        self.Customize_REG_Command_Button.setObjectName("Customize_REG_Command_Button")
        self.Develop_verticalLayout.addWidget(self.Customize_REG_Command_Button)
        self.Customize_CMD_Command_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_6)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Customize_CMD_Command_Button.sizePolicy().hasHeightForWidth())
        self.Customize_CMD_Command_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Customize_CMD_Command_Button.setFont(font)
        self.Customize_CMD_Command_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Customize_CMD_Command_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.Customize_CMD_Command_Button.setIconSize(QtCore.QSize(16, 16))
        self.Customize_CMD_Command_Button.setCheckable(False)
        self.Customize_CMD_Command_Button.setObjectName("Customize_CMD_Command_Button")
        self.Develop_verticalLayout.addWidget(self.Customize_CMD_Command_Button)
        self.Analyze_EXE_hash_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_6)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Analyze_EXE_hash_Button.sizePolicy().hasHeightForWidth())
        self.Analyze_EXE_hash_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Analyze_EXE_hash_Button.setFont(font)
        self.Analyze_EXE_hash_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Analyze_EXE_hash_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.Analyze_EXE_hash_Button.setIconSize(QtCore.QSize(16, 16))
        self.Analyze_EXE_hash_Button.setCheckable(False)
        self.Analyze_EXE_hash_Button.setObjectName("Analyze_EXE_hash_Button")
        self.Develop_verticalLayout.addWidget(self.Analyze_EXE_hash_Button)
        self.Analyze_EXE_Bit_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_6)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Analyze_EXE_Bit_Button.sizePolicy().hasHeightForWidth())
        self.Analyze_EXE_Bit_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Analyze_EXE_Bit_Button.setFont(font)
        self.Analyze_EXE_Bit_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Analyze_EXE_Bit_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.Analyze_EXE_Bit_Button.setIconSize(QtCore.QSize(16, 16))
        self.Analyze_EXE_Bit_Button.setCheckable(False)
        self.Analyze_EXE_Bit_Button.setObjectName("Analyze_EXE_Bit_Button")
        self.Develop_verticalLayout.addWidget(self.Analyze_EXE_Bit_Button)
        self.Analyze_EXE_Funtion_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_6)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Analyze_EXE_Funtion_Button.sizePolicy().hasHeightForWidth())
        self.Analyze_EXE_Funtion_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Analyze_EXE_Funtion_Button.setFont(font)
        self.Analyze_EXE_Funtion_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Analyze_EXE_Funtion_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.Analyze_EXE_Funtion_Button.setIconSize(QtCore.QSize(16, 16))
        self.Analyze_EXE_Funtion_Button.setCheckable(False)
        self.Analyze_EXE_Funtion_Button.setObjectName("Analyze_EXE_Funtion_Button")
        self.Develop_verticalLayout.addWidget(self.Analyze_EXE_Funtion_Button)
        self.Look_for_File_widget = QtWidgets.QWidget(self.widget)
        self.Look_for_File_widget.setGeometry(QtCore.QRect(170, 50, 671, 481))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Look_for_File_widget.setFont(font)
        self.Look_for_File_widget.setStyleSheet("background-color:rgba(255, 255, 255,240);")
        self.Look_for_File_widget.setObjectName("Look_for_File_widget")
        self.Look_for_File_Back = QtWidgets.QPushButton(self.Look_for_File_widget)
        self.Look_for_File_Back.setGeometry(QtCore.QRect(10, 10, 101, 41))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Look_for_File_Back.sizePolicy().hasHeightForWidth())
        self.Look_for_File_Back.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Look_for_File_Back.setFont(font)
        self.Look_for_File_Back.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Look_for_File_Back.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    color:rgba(60,60,60,200);\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    color:rgba(60,60,60,255);\n"
"}\n"
"")
        self.Look_for_File_Back.setIcon(icon1)
        self.Look_for_File_Back.setIconSize(QtCore.QSize(20, 20))
        self.Look_for_File_Back.setCheckable(False)
        self.Look_for_File_Back.setObjectName("Look_for_File_Back")
        self.Look_for_File_Run_Button = QtWidgets.QPushButton(self.Look_for_File_widget)
        self.Look_for_File_Run_Button.setGeometry(QtCore.QRect(540, 70, 101, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Look_for_File_Run_Button.sizePolicy().hasHeightForWidth())
        self.Look_for_File_Run_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Look_for_File_Run_Button.setFont(font)
        self.Look_for_File_Run_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Look_for_File_Run_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.Look_for_File_Run_Button.setIconSize(QtCore.QSize(16, 16))
        self.Look_for_File_Run_Button.setCheckable(False)
        self.Look_for_File_Run_Button.setObjectName("Look_for_File_Run_Button")
        self.Look_for_File_input = QtWidgets.QLineEdit(self.Look_for_File_widget)
        self.Look_for_File_input.setGeometry(QtCore.QRect(30, 70, 501, 31))
        self.Look_for_File_input.setObjectName("Look_for_File_input")
        self.Look_for_File_output = QtWidgets.QTextEdit(self.Look_for_File_widget)
        self.Look_for_File_output.setGeometry(QtCore.QRect(30, 120, 611, 331))
        self.Look_for_File_output.setObjectName("Look_for_File_output")
        self.Privacy_Tools_widget = QtWidgets.QWidget(self.widget)
        self.Privacy_Tools_widget.setGeometry(QtCore.QRect(170, 50, 671, 481))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Privacy_Tools_widget.setFont(font)
        self.Privacy_Tools_widget.setStyleSheet("background-color:rgba(255, 255, 255,240);")
        self.Privacy_Tools_widget.setObjectName("Privacy_Tools_widget")
        self.Privacy_Tools_Back = QtWidgets.QPushButton(self.Privacy_Tools_widget)
        self.Privacy_Tools_Back.setGeometry(QtCore.QRect(10, 10, 101, 41))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Privacy_Tools_Back.sizePolicy().hasHeightForWidth())
        self.Privacy_Tools_Back.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Privacy_Tools_Back.setFont(font)
        self.Privacy_Tools_Back.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Privacy_Tools_Back.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    color:rgba(60,60,60,200);\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    color:rgba(60,60,60,255);\n"
"}\n"
"")
        self.Privacy_Tools_Back.setIcon(icon1)
        self.Privacy_Tools_Back.setIconSize(QtCore.QSize(20, 20))
        self.Privacy_Tools_Back.setCheckable(False)
        self.Privacy_Tools_Back.setObjectName("Privacy_Tools_Back")
        self.verticalLayoutWidget_5 = QtWidgets.QWidget(self.Privacy_Tools_widget)
        self.verticalLayoutWidget_5.setGeometry(QtCore.QRect(20, 60, 631, 91))
        self.verticalLayoutWidget_5.setObjectName("verticalLayoutWidget_5")
        self.Private_verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_5)
        self.Private_verticalLayout.setContentsMargins(10, 10, 10, 10)
        self.Private_verticalLayout.setSpacing(5)
        self.Private_verticalLayout.setObjectName("Private_verticalLayout")
        self.Delete_Private_File_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_5)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Delete_Private_File_Button.sizePolicy().hasHeightForWidth())
        self.Delete_Private_File_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Delete_Private_File_Button.setFont(font)
        self.Delete_Private_File_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Delete_Private_File_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.Delete_Private_File_Button.setIconSize(QtCore.QSize(16, 16))
        self.Delete_Private_File_Button.setCheckable(False)
        self.Delete_Private_File_Button.setObjectName("Delete_Private_File_Button")
        self.Private_verticalLayout.addWidget(self.Delete_Private_File_Button)
        self.About_widget = QtWidgets.QWidget(self.widget)
        self.About_widget.setGeometry(QtCore.QRect(170, 50, 671, 481))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.About_widget.setFont(font)
        self.About_widget.setStyleSheet("background-color:rgba(255, 255, 255,255);")
        self.About_widget.setObjectName("About_widget")
        self.About_Back = QtWidgets.QPushButton(self.About_widget)
        self.About_Back.setGeometry(QtCore.QRect(10, 10, 101, 41))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.About_Back.sizePolicy().hasHeightForWidth())
        self.About_Back.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.About_Back.setFont(font)
        self.About_Back.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.About_Back.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    color:rgba(60,60,60,200);\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    color:rgba(60,60,60,255);\n"
"}\n"
"")
        self.About_Back.setIcon(icon1)
        self.About_Back.setIconSize(QtCore.QSize(20, 20))
        self.About_Back.setCheckable(False)
        self.About_Back.setObjectName("About_Back")
        self.PYAS_Version = QtWidgets.QLabel(self.About_widget)
        self.PYAS_Version.setGeometry(QtCore.QRect(30, 50, 131, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(14)
        font.setBold(False)
        font.setUnderline(False)
        font.setWeight(50)
        self.PYAS_Version.setFont(font)
        self.PYAS_Version.setStyleSheet("")
        self.PYAS_Version.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.PYAS_Version.setObjectName("PYAS_Version")
        self.GUI_Made_title = QtWidgets.QLabel(self.About_widget)
        self.GUI_Made_title.setGeometry(QtCore.QRect(30, 100, 131, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setBold(False)
        font.setWeight(50)
        self.GUI_Made_title.setFont(font)
        self.GUI_Made_title.setStyleSheet("")
        self.GUI_Made_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.GUI_Made_title.setObjectName("GUI_Made_title")
        self.GUI_Made_Name = QtWidgets.QLabel(self.About_widget)
        self.GUI_Made_Name.setGeometry(QtCore.QRect(190, 100, 451, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setBold(False)
        font.setWeight(50)
        self.GUI_Made_Name.setFont(font)
        self.GUI_Made_Name.setStyleSheet("")
        self.GUI_Made_Name.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.GUI_Made_Name.setObjectName("GUI_Made_Name")
        self.Core_Made_title = QtWidgets.QLabel(self.About_widget)
        self.Core_Made_title.setGeometry(QtCore.QRect(30, 140, 131, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setBold(False)
        font.setWeight(50)
        self.Core_Made_title.setFont(font)
        self.Core_Made_title.setStyleSheet("")
        self.Core_Made_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Core_Made_title.setObjectName("Core_Made_title")
        self.Core_Made_Name = QtWidgets.QLabel(self.About_widget)
        self.Core_Made_Name.setGeometry(QtCore.QRect(190, 140, 451, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setBold(False)
        font.setWeight(50)
        self.Core_Made_Name.setFont(font)
        self.Core_Made_Name.setStyleSheet("")
        self.Core_Made_Name.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Core_Made_Name.setObjectName("Core_Made_Name")
        self.Testers_title = QtWidgets.QLabel(self.About_widget)
        self.Testers_title.setGeometry(QtCore.QRect(30, 180, 131, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setBold(False)
        font.setWeight(50)
        self.Testers_title.setFont(font)
        self.Testers_title.setStyleSheet("")
        self.Testers_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Testers_title.setObjectName("Testers_title")
        self.Testers_Name = QtWidgets.QLabel(self.About_widget)
        self.Testers_Name.setGeometry(QtCore.QRect(190, 180, 451, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setBold(False)
        font.setWeight(50)
        self.Testers_Name.setFont(font)
        self.Testers_Name.setStyleSheet("")
        self.Testers_Name.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Testers_Name.setObjectName("Testers_Name")
        self.PYAS_URL_title = QtWidgets.QLabel(self.About_widget)
        self.PYAS_URL_title.setGeometry(QtCore.QRect(30, 220, 131, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setBold(False)
        font.setWeight(50)
        self.PYAS_URL_title.setFont(font)
        self.PYAS_URL_title.setStyleSheet("")
        self.PYAS_URL_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.PYAS_URL_title.setObjectName("PYAS_URL_title")
        self.PYAS_URL = QtWidgets.QLabel(self.About_widget)
        self.PYAS_URL.setGeometry(QtCore.QRect(190, 220, 451, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setBold(False)
        font.setWeight(50)
        self.PYAS_URL.setFont(font)
        self.PYAS_URL.setStyleSheet("")
        self.PYAS_URL.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.PYAS_URL.setOpenExternalLinks(True)
        self.PYAS_URL.setObjectName("PYAS_URL")
        self.PYAS_CopyRight = QtWidgets.QLabel(self.About_widget)
        self.PYAS_CopyRight.setGeometry(QtCore.QRect(30, 430, 611, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setBold(False)
        font.setWeight(50)
        self.PYAS_CopyRight.setFont(font)
        self.PYAS_CopyRight.setStyleSheet("")
        self.PYAS_CopyRight.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.PYAS_CopyRight.setObjectName("PYAS_CopyRight")
        self.PYAE_Version = QtWidgets.QLabel(self.About_widget)
        self.PYAE_Version.setGeometry(QtCore.QRect(190, 50, 451, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(14)
        font.setBold(False)
        font.setUnderline(False)
        font.setWeight(50)
        self.PYAE_Version.setFont(font)
        self.PYAE_Version.setStyleSheet("")
        self.PYAE_Version.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.PYAE_Version.setObjectName("PYAE_Version")
        self.License_terms = QtWidgets.QTextEdit(self.About_widget)
        self.License_terms.setGeometry(QtCore.QRect(30, 310, 611, 121))
        self.License_terms.setStyleSheet("")
        self.License_terms.setReadOnly(True)
        self.License_terms.setObjectName("License_terms")
        self.License_terms_title = QtWidgets.QLabel(self.About_widget)
        self.License_terms_title.setGeometry(QtCore.QRect(30, 260, 611, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setBold(False)
        font.setWeight(50)
        self.License_terms_title.setFont(font)
        self.License_terms_title.setStyleSheet("")
        self.License_terms_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.License_terms_title.setObjectName("License_terms_title")
        self.Customize_REG_Command_widget = QtWidgets.QWidget(self.widget)
        self.Customize_REG_Command_widget.setGeometry(QtCore.QRect(170, 50, 671, 481))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Customize_REG_Command_widget.setFont(font)
        self.Customize_REG_Command_widget.setStyleSheet("background-color:rgba(255, 255, 255,240);")
        self.Customize_REG_Command_widget.setObjectName("Customize_REG_Command_widget")
        self.Customize_REG_Command_Back = QtWidgets.QPushButton(self.Customize_REG_Command_widget)
        self.Customize_REG_Command_Back.setGeometry(QtCore.QRect(10, 10, 101, 41))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Customize_REG_Command_Back.sizePolicy().hasHeightForWidth())
        self.Customize_REG_Command_Back.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Customize_REG_Command_Back.setFont(font)
        self.Customize_REG_Command_Back.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Customize_REG_Command_Back.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    color:rgba(60,60,60,200);\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    color:rgba(60,60,60,255);\n"
"}\n"
"")
        self.Customize_REG_Command_Back.setIcon(icon1)
        self.Customize_REG_Command_Back.setIconSize(QtCore.QSize(20, 20))
        self.Customize_REG_Command_Back.setCheckable(False)
        self.Customize_REG_Command_Back.setObjectName("Customize_REG_Command_Back")
        self.Value_Path_title = QtWidgets.QLabel(self.Customize_REG_Command_widget)
        self.Value_Path_title.setGeometry(QtCore.QRect(30, 80, 161, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.Value_Path_title.setFont(font)
        self.Value_Path_title.setStyleSheet("")
        self.Value_Path_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Value_Path_title.setObjectName("Value_Path_title")
        self.Value_Name_title = QtWidgets.QLabel(self.Customize_REG_Command_widget)
        self.Value_Name_title.setGeometry(QtCore.QRect(30, 120, 161, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.Value_Name_title.setFont(font)
        self.Value_Name_title.setStyleSheet("")
        self.Value_Name_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Value_Name_title.setObjectName("Value_Name_title")
        self.Value_Type_title = QtWidgets.QLabel(self.Customize_REG_Command_widget)
        self.Value_Type_title.setGeometry(QtCore.QRect(30, 160, 161, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.Value_Type_title.setFont(font)
        self.Value_Type_title.setStyleSheet("")
        self.Value_Type_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Value_Type_title.setObjectName("Value_Type_title")
        self.Value_Data_title = QtWidgets.QLabel(self.Customize_REG_Command_widget)
        self.Value_Data_title.setGeometry(QtCore.QRect(30, 200, 161, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.Value_Data_title.setFont(font)
        self.Value_Data_title.setStyleSheet("")
        self.Value_Data_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Value_Data_title.setObjectName("Value_Data_title")
        self.Value_Path_input = QtWidgets.QLineEdit(self.Customize_REG_Command_widget)
        self.Value_Path_input.setGeometry(QtCore.QRect(190, 80, 441, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Value_Path_input.setFont(font)
        self.Value_Path_input.setObjectName("Value_Path_input")
        self.Value_Type_input = QtWidgets.QLineEdit(self.Customize_REG_Command_widget)
        self.Value_Type_input.setGeometry(QtCore.QRect(190, 160, 441, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Value_Type_input.setFont(font)
        self.Value_Type_input.setObjectName("Value_Type_input")
        self.Value_Name_input = QtWidgets.QLineEdit(self.Customize_REG_Command_widget)
        self.Value_Name_input.setGeometry(QtCore.QRect(190, 120, 441, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Value_Name_input.setFont(font)
        self.Value_Name_input.setObjectName("Value_Name_input")
        self.Value_Data_input = QtWidgets.QLineEdit(self.Customize_REG_Command_widget)
        self.Value_Data_input.setGeometry(QtCore.QRect(190, 200, 441, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Value_Data_input.setFont(font)
        self.Value_Data_input.setObjectName("Value_Data_input")
        self.Customize_REG_Command_Run_Button = QtWidgets.QPushButton(self.Customize_REG_Command_widget)
        self.Customize_REG_Command_Run_Button.setGeometry(QtCore.QRect(270, 290, 91, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Customize_REG_Command_Run_Button.sizePolicy().hasHeightForWidth())
        self.Customize_REG_Command_Run_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Customize_REG_Command_Run_Button.setFont(font)
        self.Customize_REG_Command_Run_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Customize_REG_Command_Run_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.Customize_REG_Command_Run_Button.setIconSize(QtCore.QSize(16, 16))
        self.Customize_REG_Command_Run_Button.setCheckable(False)
        self.Customize_REG_Command_Run_Button.setObjectName("Customize_REG_Command_Run_Button")
        self.Value_HEKY_title = QtWidgets.QLabel(self.Customize_REG_Command_widget)
        self.Value_HEKY_title.setGeometry(QtCore.QRect(30, 240, 161, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.Value_HEKY_title.setFont(font)
        self.Value_HEKY_title.setStyleSheet("")
        self.Value_HEKY_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Value_HEKY_title.setObjectName("Value_HEKY_title")
        self.Value_HEKY_input = QtWidgets.QLineEdit(self.Customize_REG_Command_widget)
        self.Value_HEKY_input.setGeometry(QtCore.QRect(190, 240, 441, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Value_HEKY_input.setFont(font)
        self.Value_HEKY_input.setObjectName("Value_HEKY_input")
        self.Window_widget = QtWidgets.QWidget(self.widget)
        self.Window_widget.setGeometry(QtCore.QRect(10, 10, 831, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Window_widget.setFont(font)
        self.Window_widget.setStyleSheet("QWidget#Window_widget\n"
"{\n"
"background-color:rgb(240, 240, 240);\n"
"}")
        self.Window_widget.setObjectName("Window_widget")
        self.Close_Button = QtWidgets.QPushButton(self.Window_widget)
        self.Close_Button.setGeometry(QtCore.QRect(790, 5, 31, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Close_Button.sizePolicy().hasHeightForWidth())
        self.Close_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Close_Button.setFont(font)
        self.Close_Button.setCursor(QtGui.QCursor(QtCore.Qt.ArrowCursor))
        self.Close_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Close_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(255, 255, 255,150);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(255, 255, 255,220);\n"
"}")
        self.Close_Button.setText("")
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap(":/icon/Icon/X.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Close_Button.setIcon(icon3)
        self.Close_Button.setIconSize(QtCore.QSize(13, 13))
        self.Close_Button.setCheckable(False)
        self.Close_Button.setObjectName("Close_Button")
        self.Minimize_Button = QtWidgets.QPushButton(self.Window_widget)
        self.Minimize_Button.setGeometry(QtCore.QRect(755, 5, 31, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Minimize_Button.sizePolicy().hasHeightForWidth())
        self.Minimize_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Minimize_Button.setFont(font)
        self.Minimize_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Minimize_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(255, 255, 255,150);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(255, 255, 255,220);\n"
"}")
        self.Minimize_Button.setText("")
        icon4 = QtGui.QIcon()
        icon4.addPixmap(QtGui.QPixmap(":/icon/Icon/minimizeIcon.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Minimize_Button.setIcon(icon4)
        self.Minimize_Button.setIconSize(QtCore.QSize(20, 20))
        self.Minimize_Button.setCheckable(False)
        self.Minimize_Button.setObjectName("Minimize_Button")
        self.Window_title = QtWidgets.QLabel(self.Window_widget)
        self.Window_title.setGeometry(QtCore.QRect(10, 0, 691, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(14)
        font.setBold(False)
        font.setWeight(50)
        self.Window_title.setFont(font)
        self.Window_title.setStyleSheet("")
        self.Window_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Window_title.setObjectName("Window_title")
        self.Menu_Button = QtWidgets.QToolButton(self.Window_widget)
        self.Menu_Button.setGeometry(QtCore.QRect(720, 5, 31, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Menu_Button.sizePolicy().hasHeightForWidth())
        self.Menu_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Menu_Button.setFont(font)
        self.Menu_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Menu_Button.setStyleSheet("QToolButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    border-radius: 15px;\n"
"}\n"
"QToolButton:hover\n"
"{\n"
"    background-color:rgba(255, 255, 255,150);\n"
"}\n"
"QToolButton:pressed\n"
"{\n"
"    background-color:rgba(255, 255, 255,220);\n"
"}")
        self.Menu_Button.setText("")
        icon5 = QtGui.QIcon()
        icon5.addPixmap(QtGui.QPixmap(":/icon/Icon/Menu.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Menu_Button.setIcon(icon5)
        self.Menu_Button.setIconSize(QtCore.QSize(19, 19))
        self.Menu_Button.setCheckable(False)
        self.Menu_Button.setObjectName("Menu_Button")
        self.Process_widget = QtWidgets.QWidget(self.widget)
        self.Process_widget.setGeometry(QtCore.QRect(170, 50, 671, 481))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Process_widget.setFont(font)
        self.Process_widget.setStyleSheet("background-color:rgba(255, 255, 255,240);")
        self.Process_widget.setObjectName("Process_widget")
        self.Process_Tools_Back = QtWidgets.QPushButton(self.Process_widget)
        self.Process_Tools_Back.setGeometry(QtCore.QRect(10, 10, 101, 41))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Process_Tools_Back.sizePolicy().hasHeightForWidth())
        self.Process_Tools_Back.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Process_Tools_Back.setFont(font)
        self.Process_Tools_Back.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Process_Tools_Back.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    color:rgba(60,60,60,200);\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    color:rgba(60,60,60,255);\n"
"}\n"
"")
        self.Process_Tools_Back.setIcon(icon1)
        self.Process_Tools_Back.setIconSize(QtCore.QSize(20, 20))
        self.Process_Tools_Back.setCheckable(False)
        self.Process_Tools_Back.setObjectName("Process_Tools_Back")
        self.Process_list = QtWidgets.QListView(self.Process_widget)
        self.Process_list.setGeometry(QtCore.QRect(30, 60, 611, 361))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        self.Process_list.setFont(font)
        self.Process_list.setStyleSheet("QWidget::item\n"
"{\n"
"background-color: rgba(50,50,50,30);\n"
"color:black;\n"
"border: transparent;\n"
"border-bottom: 1px solid #dbdbdb;\n"
"padding: 5px;\n"
"}\n"
"QWidget::item:hover\n"
"{\n"
"background-color: rgba(50,50,50,40);\n"
"}\n"
"QListView\n"
"{\n"
"outline: none;\n"
"}")
        self.Process_list.setAutoScroll(True)
        self.Process_list.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.Process_list.setTabKeyNavigation(True)
        self.Process_list.setProperty("showDropIndicator", True)
        self.Process_list.setDragDropOverwriteMode(True)
        self.Process_list.setDragDropMode(QtWidgets.QAbstractItemView.NoDragDrop)
        self.Process_list.setDefaultDropAction(QtCore.Qt.IgnoreAction)
        self.Process_list.setAlternatingRowColors(False)
        self.Process_list.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.Process_list.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.Process_list.setTextElideMode(QtCore.Qt.ElideRight)
        self.Process_list.setVerticalScrollMode(QtWidgets.QAbstractItemView.ScrollPerItem)
        self.Process_list.setObjectName("Process_list")
        self.Process_Total_title = QtWidgets.QLabel(self.Process_widget)
        self.Process_Total_title.setGeometry(QtCore.QRect(30, 425, 141, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.Process_Total_title.setFont(font)
        self.Process_Total_title.setStyleSheet("")
        self.Process_Total_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Process_Total_title.setObjectName("Process_Total_title")
        self.Process_Total_View = QtWidgets.QLineEdit(self.Process_widget)
        self.Process_Total_View.setGeometry(QtCore.QRect(180, 430, 461, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Process_Total_View.setFont(font)
        self.Process_Total_View.setReadOnly(True)
        self.Process_Total_View.setObjectName("Process_Total_View")
        self.System_Tools_widget = QtWidgets.QWidget(self.widget)
        self.System_Tools_widget.setGeometry(QtCore.QRect(170, 50, 671, 481))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.System_Tools_widget.setFont(font)
        self.System_Tools_widget.setStyleSheet("background-color:rgba(255, 255, 255,240);")
        self.System_Tools_widget.setObjectName("System_Tools_widget")
        self.verticalLayoutWidget_4 = QtWidgets.QWidget(self.System_Tools_widget)
        self.verticalLayoutWidget_4.setGeometry(QtCore.QRect(20, 60, 631, 401))
        self.verticalLayoutWidget_4.setObjectName("verticalLayoutWidget_4")
        self.System_verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_4)
        self.System_verticalLayout.setContentsMargins(10, 10, 10, 10)
        self.System_verticalLayout.setSpacing(5)
        self.System_verticalLayout.setObjectName("System_verticalLayout")
        self.System_Process_Manage_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_4)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.System_Process_Manage_Button.sizePolicy().hasHeightForWidth())
        self.System_Process_Manage_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.System_Process_Manage_Button.setFont(font)
        self.System_Process_Manage_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.System_Process_Manage_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.System_Process_Manage_Button.setIconSize(QtCore.QSize(16, 16))
        self.System_Process_Manage_Button.setCheckable(False)
        self.System_Process_Manage_Button.setObjectName("System_Process_Manage_Button")
        self.System_verticalLayout.addWidget(self.System_Process_Manage_Button)
        self.Repair_System_Files_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_4)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Repair_System_Files_Button.sizePolicy().hasHeightForWidth())
        self.Repair_System_Files_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Repair_System_Files_Button.setFont(font)
        self.Repair_System_Files_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Repair_System_Files_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.Repair_System_Files_Button.setIconSize(QtCore.QSize(16, 16))
        self.Repair_System_Files_Button.setCheckable(False)
        self.Repair_System_Files_Button.setObjectName("Repair_System_Files_Button")
        self.System_verticalLayout.addWidget(self.Repair_System_Files_Button)
        self.Clean_System_Files_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_4)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Clean_System_Files_Button.sizePolicy().hasHeightForWidth())
        self.Clean_System_Files_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Clean_System_Files_Button.setFont(font)
        self.Clean_System_Files_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Clean_System_Files_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.Clean_System_Files_Button.setIconSize(QtCore.QSize(16, 16))
        self.Clean_System_Files_Button.setCheckable(False)
        self.Clean_System_Files_Button.setObjectName("Clean_System_Files_Button")
        self.System_verticalLayout.addWidget(self.Clean_System_Files_Button)
        self.Enable_Safe_Mode_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_4)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Enable_Safe_Mode_Button.sizePolicy().hasHeightForWidth())
        self.Enable_Safe_Mode_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Enable_Safe_Mode_Button.setFont(font)
        self.Enable_Safe_Mode_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Enable_Safe_Mode_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.Enable_Safe_Mode_Button.setIconSize(QtCore.QSize(16, 16))
        self.Enable_Safe_Mode_Button.setCheckable(False)
        self.Enable_Safe_Mode_Button.setObjectName("Enable_Safe_Mode_Button")
        self.System_verticalLayout.addWidget(self.Enable_Safe_Mode_Button)
        self.Disable_Safe_Mode_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_4)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Disable_Safe_Mode_Button.sizePolicy().hasHeightForWidth())
        self.Disable_Safe_Mode_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Disable_Safe_Mode_Button.setFont(font)
        self.Disable_Safe_Mode_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Disable_Safe_Mode_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.Disable_Safe_Mode_Button.setIconSize(QtCore.QSize(16, 16))
        self.Disable_Safe_Mode_Button.setCheckable(False)
        self.Disable_Safe_Mode_Button.setObjectName("Disable_Safe_Mode_Button")
        self.System_verticalLayout.addWidget(self.Disable_Safe_Mode_Button)
        self.System_Info_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_4)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.System_Info_Button.sizePolicy().hasHeightForWidth())
        self.System_Info_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.System_Info_Button.setFont(font)
        self.System_Info_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.System_Info_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.System_Info_Button.setIconSize(QtCore.QSize(16, 16))
        self.System_Info_Button.setCheckable(False)
        self.System_Info_Button.setObjectName("System_Info_Button")
        self.System_verticalLayout.addWidget(self.System_Info_Button)
        self.System_Tools_Back = QtWidgets.QPushButton(self.System_Tools_widget)
        self.System_Tools_Back.setGeometry(QtCore.QRect(10, 10, 101, 41))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.System_Tools_Back.sizePolicy().hasHeightForWidth())
        self.System_Tools_Back.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.System_Tools_Back.setFont(font)
        self.System_Tools_Back.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.System_Tools_Back.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    color:rgba(60,60,60,200);\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    color:rgba(60,60,60,255);\n"
"}\n"
"")
        self.System_Tools_Back.setIcon(icon1)
        self.System_Tools_Back.setIconSize(QtCore.QSize(20, 20))
        self.System_Tools_Back.setCheckable(False)
        self.System_Tools_Back.setObjectName("System_Tools_Back")
        self.Analyze_EXE_widget = QtWidgets.QWidget(self.widget)
        self.Analyze_EXE_widget.setGeometry(QtCore.QRect(170, 50, 671, 481))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Analyze_EXE_widget.setFont(font)
        self.Analyze_EXE_widget.setStyleSheet("background-color:rgba(255, 255, 255,240);")
        self.Analyze_EXE_widget.setObjectName("Analyze_EXE_widget")
        self.Analyze_EXE_Back = QtWidgets.QPushButton(self.Analyze_EXE_widget)
        self.Analyze_EXE_Back.setGeometry(QtCore.QRect(10, 10, 101, 41))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Analyze_EXE_Back.sizePolicy().hasHeightForWidth())
        self.Analyze_EXE_Back.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Analyze_EXE_Back.setFont(font)
        self.Analyze_EXE_Back.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Analyze_EXE_Back.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    color:rgba(60,60,60,200);\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    color:rgba(60,60,60,255);\n"
"}\n"
"")
        self.Analyze_EXE_Back.setIcon(icon1)
        self.Analyze_EXE_Back.setIconSize(QtCore.QSize(20, 20))
        self.Analyze_EXE_Back.setCheckable(False)
        self.Analyze_EXE_Back.setObjectName("Analyze_EXE_Back")
        self.Analyze_EXE_Output = QtWidgets.QTextEdit(self.Analyze_EXE_widget)
        self.Analyze_EXE_Output.setGeometry(QtCore.QRect(30, 60, 611, 391))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Analyze_EXE_Output.setFont(font)
        self.Analyze_EXE_Output.setReadOnly(True)
        self.Analyze_EXE_Output.setObjectName("Analyze_EXE_Output")
        self.Customize_CMD_Command_widget = QtWidgets.QWidget(self.widget)
        self.Customize_CMD_Command_widget.setGeometry(QtCore.QRect(170, 50, 671, 481))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Customize_CMD_Command_widget.setFont(font)
        self.Customize_CMD_Command_widget.setStyleSheet("background-color:rgba(255, 255, 255,240);")
        self.Customize_CMD_Command_widget.setObjectName("Customize_CMD_Command_widget")
        self.Customize_CMD_Command_Back = QtWidgets.QPushButton(self.Customize_CMD_Command_widget)
        self.Customize_CMD_Command_Back.setGeometry(QtCore.QRect(10, 10, 101, 41))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Customize_CMD_Command_Back.sizePolicy().hasHeightForWidth())
        self.Customize_CMD_Command_Back.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Customize_CMD_Command_Back.setFont(font)
        self.Customize_CMD_Command_Back.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Customize_CMD_Command_Back.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    color:rgba(60,60,60,200);\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    color:rgba(60,60,60,255);\n"
"}\n"
"")
        self.Customize_CMD_Command_Back.setIcon(icon1)
        self.Customize_CMD_Command_Back.setIconSize(QtCore.QSize(20, 20))
        self.Customize_CMD_Command_Back.setCheckable(False)
        self.Customize_CMD_Command_Back.setObjectName("Customize_CMD_Command_Back")
        self.Customize_CMD_Command_lineEdit = QtWidgets.QLineEdit(self.Customize_CMD_Command_widget)
        self.Customize_CMD_Command_lineEdit.setGeometry(QtCore.QRect(30, 70, 511, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Customize_CMD_Command_lineEdit.setFont(font)
        self.Customize_CMD_Command_lineEdit.setStyleSheet("")
        self.Customize_CMD_Command_lineEdit.setObjectName("Customize_CMD_Command_lineEdit")
        self.Customize_CMD_Command_Run_Button = QtWidgets.QPushButton(self.Customize_CMD_Command_widget)
        self.Customize_CMD_Command_Run_Button.setGeometry(QtCore.QRect(550, 70, 91, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Customize_CMD_Command_Run_Button.sizePolicy().hasHeightForWidth())
        self.Customize_CMD_Command_Run_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(12)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Customize_CMD_Command_Run_Button.setFont(font)
        self.Customize_CMD_Command_Run_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Customize_CMD_Command_Run_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(20,20,20,70);\n"
"}")
        self.Customize_CMD_Command_Run_Button.setIconSize(QtCore.QSize(16, 16))
        self.Customize_CMD_Command_Run_Button.setCheckable(False)
        self.Customize_CMD_Command_Run_Button.setObjectName("Customize_CMD_Command_Run_Button")
        self.Customize_CMD_Command_output = QtWidgets.QTextEdit(self.Customize_CMD_Command_widget)
        self.Customize_CMD_Command_output.setGeometry(QtCore.QRect(30, 140, 611, 311))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei UI")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Customize_CMD_Command_output.setFont(font)
        self.Customize_CMD_Command_output.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        self.Customize_CMD_Command_output.setObjectName("Customize_CMD_Command_output")
        self.Customize_CMD_Command_output_title = QtWidgets.QLabel(self.Customize_CMD_Command_widget)
        self.Customize_CMD_Command_output_title.setGeometry(QtCore.QRect(30, 105, 611, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setBold(False)
        font.setWeight(50)
        self.Customize_CMD_Command_output_title.setFont(font)
        self.Customize_CMD_Command_output_title.setStyleSheet("")
        self.Customize_CMD_Command_output_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Customize_CMD_Command_output_title.setObjectName("Customize_CMD_Command_output_title")
        self.Tools_widget = QtWidgets.QWidget(self.widget)
        self.Tools_widget.setGeometry(QtCore.QRect(170, 50, 671, 481))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Tools_widget.setFont(font)
        self.Tools_widget.setStyleSheet("background-color:rgba(255, 255, 255,240);")
        self.Tools_widget.setObjectName("Tools_widget")
        self.verticalLayoutWidget_2 = QtWidgets.QWidget(self.Tools_widget)
        self.verticalLayoutWidget_2.setGeometry(QtCore.QRect(20, 60, 631, 401))
        self.verticalLayoutWidget_2.setObjectName("verticalLayoutWidget_2")
        self.Tools_verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_2)
        self.Tools_verticalLayout.setContentsMargins(10, 10, 10, 10)
        self.Tools_verticalLayout.setSpacing(10)
        self.Tools_verticalLayout.setObjectName("Tools_verticalLayout")
        self.System_Tools_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.System_Tools_Button.sizePolicy().hasHeightForWidth())
        self.System_Tools_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(15)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.System_Tools_Button.setFont(font)
        self.System_Tools_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.System_Tools_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(50,50,50,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(50, 50, 50,65);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(40, 40, 40,70);\n"
"}")
        self.System_Tools_Button.setIconSize(QtCore.QSize(16, 16))
        self.System_Tools_Button.setCheckable(False)
        self.System_Tools_Button.setObjectName("System_Tools_Button")
        self.Tools_verticalLayout.addWidget(self.System_Tools_Button)
        self.Privacy_Tools_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Privacy_Tools_Button.sizePolicy().hasHeightForWidth())
        self.Privacy_Tools_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(15)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Privacy_Tools_Button.setFont(font)
        self.Privacy_Tools_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Privacy_Tools_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(50,50,50,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(50, 50, 50,65);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(40, 40, 40,70);\n"
"}")
        self.Privacy_Tools_Button.setIconSize(QtCore.QSize(16, 16))
        self.Privacy_Tools_Button.setCheckable(False)
        self.Privacy_Tools_Button.setObjectName("Privacy_Tools_Button")
        self.Tools_verticalLayout.addWidget(self.Privacy_Tools_Button)
        self.Develop_Tools_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Develop_Tools_Button.sizePolicy().hasHeightForWidth())
        self.Develop_Tools_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(15)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Develop_Tools_Button.setFont(font)
        self.Develop_Tools_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Develop_Tools_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(50,50,50,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(50, 50, 50,65);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(40, 40, 40,70);\n"
"}")
        self.Develop_Tools_Button.setIconSize(QtCore.QSize(16, 16))
        self.Develop_Tools_Button.setCheckable(False)
        self.Develop_Tools_Button.setObjectName("Develop_Tools_Button")
        self.Tools_verticalLayout.addWidget(self.Develop_Tools_Button)
        self.More_Tools_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.More_Tools_Button.sizePolicy().hasHeightForWidth())
        self.More_Tools_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(15)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.More_Tools_Button.setFont(font)
        self.More_Tools_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.More_Tools_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(50,50,50,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(50, 50, 50,65);\n"
"}\n"
"QPushButton:pressed\n"
"{\n"
"    background-color:rgba(40, 40, 40,70);\n"
"}")
        self.More_Tools_Button.setIconSize(QtCore.QSize(16, 16))
        self.More_Tools_Button.setCheckable(False)
        self.More_Tools_Button.setObjectName("More_Tools_Button")
        self.Tools_verticalLayout.addWidget(self.More_Tools_Button)
        self.More_Tools_Back_Button = QtWidgets.QPushButton(self.Tools_widget)
        self.More_Tools_Back_Button.setGeometry(QtCore.QRect(10, 10, 101, 41))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.More_Tools_Back_Button.sizePolicy().hasHeightForWidth())
        self.More_Tools_Back_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.More_Tools_Back_Button.setFont(font)
        self.More_Tools_Back_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.More_Tools_Back_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(0,0,0,0);\n"
"    color:rgba(60,60,60,200);\n"
"}\n"
"")
        self.More_Tools_Back_Button.setIconSize(QtCore.QSize(20, 20))
        self.More_Tools_Back_Button.setCheckable(False)
        self.More_Tools_Back_Button.setObjectName("More_Tools_Back_Button")
        self.widget_2 = QtWidgets.QWidget(self.widget)
        self.widget_2.setGeometry(QtCore.QRect(170, 50, 671, 481))
        self.widget_2.setStyleSheet("background-color:rgb(255, 255, 255);")
        self.widget_2.setObjectName("widget_2")
        self.Virus_Scan_widget.raise_()
        self.State_widget.raise_()
        self.widget_2.raise_()
        self.Change_Users_Password_widget.raise_()
        self.System_Info_widget.raise_()
        self.Develop_Tools_widget.raise_()
        self.Look_for_File_widget.raise_()
        self.Privacy_Tools_widget.raise_()
        self.About_widget.raise_()
        self.Customize_REG_Command_widget.raise_()
        self.Process_widget.raise_()
        self.System_Tools_widget.raise_()
        self.Analyze_EXE_widget.raise_()
        self.Customize_CMD_Command_widget.raise_()
        self.Tools_widget.raise_()
        self.Setting_widget.raise_()
        self.More_Tools_widget.raise_()
        self.Encryption_Text_widget.raise_()
        self.Protection_widget.raise_()
        self.Window_widget.raise_()
        self.Navigation_Bar.raise_()
        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "PYAS"))
        self.high_sensitivity_title.setText(_translate("MainWindow", "高靈敏度模式"))
        self.high_sensitivity_illustrate.setText(_translate("MainWindow", "開啟此選項後可提高掃描時的靈敏度，但這也可能會導致誤殺。"))
        self.high_sensitivity_switch_Button.setText(_translate("MainWindow", "已關閉"))
        self.Setting_Back.setText(_translate("MainWindow", "返回"))
        self.Language_title.setText(_translate("MainWindow", "語言"))
        self.Language_illustrate.setText(_translate("MainWindow", "請選擇語言"))
        self.Language_Traditional_Chinese.setText(_translate("MainWindow", "繁體中文"))
        self.Language_Simplified_Chinese.setText(_translate("MainWindow", "简体中文"))
        self.Languahe_English.setText(_translate("MainWindow", "English"))
        self.Theme_title.setText(_translate("MainWindow", "顯色主題"))
        self.Theme_illustrate.setText(_translate("MainWindow", "請選擇主題"))
        self.Theme_Black.setText(_translate("MainWindow", "黑色主題"))
        self.Theme_White.setText(_translate("MainWindow", "白色主題"))
        self.Theme_Pink.setText(_translate("MainWindow", "粉色主題"))
        self.Theme_Blue.setText(_translate("MainWindow", "藍色主題"))
        self.Theme_Red.setText(_translate("MainWindow", "紅色主題"))
        self.Theme_Green.setText(_translate("MainWindow", "綠色主題"))
        self.More_Tools_Back.setText(_translate("MainWindow", "返回"))
        self.Look_for_File_Button.setText(_translate("MainWindow", "尋找檔案"))
        self.Encryption_Text_Button.setText(_translate("MainWindow", "加密文字"))
        self.Change_Users_Password_Button.setText(_translate("MainWindow", "變更用戶密碼"))
        self.Internet_location_Query_Button.setText(_translate("MainWindow", "網路位置查詢"))
        self.Rework_Network_Configuration_Button.setText(_translate("MainWindow", "重置網路配置"))
        self.Encryption_Text_Back.setText(_translate("MainWindow", "返回"))
        self.Encryption_Text_Run_Button.setText(_translate("MainWindow", "加密"))
        self.Encryption_Text_title2.setText(_translate("MainWindow", "加密&解密後"))
        self.Encryption_Text_Password_title.setText(_translate("MainWindow", "密碼:"))
        self.Encryption_Text_title.setText(_translate("MainWindow", "加密&解密前"))
        self.Decrypt_Text_Run_Button.setText(_translate("MainWindow", "解密"))
        self.Protection_title.setText(_translate("MainWindow", "進程防護"))
        self.Protection_illustrate.setText(_translate("MainWindow", "啟用該選項可以實時監控進程中的惡意軟體並清除"))
        self.Protection_switch_Button.setText(_translate("MainWindow", "已關閉"))
        self.State_Button.setText(_translate("MainWindow", "狀態"))
        self.Virus_Scan_Button.setText(_translate("MainWindow", "掃描"))
        self.Tools_Button.setText(_translate("MainWindow", "工具"))
        self.Protection_Button.setText(_translate("MainWindow", "防護"))
        self.Virus_Scan_title.setText(_translate("MainWindow", "病毒掃描"))
        self.Virus_Scan_text.setText(_translate("MainWindow", "請選擇掃描方式"))
        self.Virus_Scan_choose_Button.setText(_translate("MainWindow", "病毒掃描"))
        self.File_Scan_Button.setText(_translate("MainWindow", "檔案掃描"))
        self.Path_Scan_Button.setText(_translate("MainWindow", "路徑掃描"))
        self.Disk_Scan_Button.setText(_translate("MainWindow", "全盤掃描"))
        self.Virus_Scan_Solve_Button.setText(_translate("MainWindow", "立即解決"))
        self.Virus_Scan_Break_Button.setText(_translate("MainWindow", "停止掃描"))
        self.State_title.setText(_translate("MainWindow", "這台電腦目前很安全"))
        self.State_log.setText(_translate("MainWindow", "日誌:"))
        self.Change_Users_Password_Back.setText(_translate("MainWindow", "返回"))
        self.Change_Users_Password_New_Password_title.setText(_translate("MainWindow", "新密碼:"))
        self.Change_Users_Password_User_Name_title.setText(_translate("MainWindow", "用戶名:"))
        self.Change_Users_Password_Run_Button.setText(_translate("MainWindow", "修改"))
        self.System_Info_Back.setText(_translate("MainWindow", "返回"))
        self.Develop_Tools_Back.setText(_translate("MainWindow", "返回"))
        self.Customize_REG_Command_Button.setText(_translate("MainWindow", "自訂REG指令"))
        self.Customize_CMD_Command_Button.setText(_translate("MainWindow", "自訂CMD指令"))
        self.Analyze_EXE_hash_Button.setText(_translate("MainWindow", "分析EXE哈希"))
        self.Analyze_EXE_Bit_Button.setText(_translate("MainWindow", "分析EXE位元"))
        self.Analyze_EXE_Funtion_Button.setText(_translate("MainWindow", "分析EXE函數"))
        self.Look_for_File_Back.setText(_translate("MainWindow", "返回"))
        self.Look_for_File_Run_Button.setText(_translate("MainWindow", "尋找檔案"))
        self.Privacy_Tools_Back.setText(_translate("MainWindow", "返回"))
        self.Delete_Private_File_Button.setText(_translate("MainWindow", "刪除隱私檔案"))
        self.About_Back.setText(_translate("MainWindow", "返回"))
        self.PYAS_Version.setText(_translate("MainWindow", "PYAS  v2.3.5"))
        self.GUI_Made_title.setText(_translate("MainWindow", "介面製作:"))
        self.GUI_Made_Name.setText(_translate("MainWindow", "mtkiao129#3921"))
        self.Core_Made_title.setText(_translate("MainWindow", "核心製作:"))
        self.Core_Made_Name.setText(_translate("MainWindow", "PYAS_Dev#0629"))
        self.Testers_title.setText(_translate("MainWindow", "測試人員:"))
        self.Testers_Name.setText(_translate("MainWindow", "mtkiao129#3921"))
        self.PYAS_URL_title.setText(_translate("MainWindow", "官方網站:"))
        self.PYAS_URL.setText(_translate("MainWindow", "<html><head/><body><p><a href=\"https://xiaomi69ai.wixsite.com/pyas\"><span style=\" text-decoration: underline; color:#0000ff;\">https://xiaomi69ai.wixsite.com/pyas</span></a></p></body></html>"))
        self.PYAS_CopyRight.setText(_translate("MainWindow", "Copyright© 2020-2022 PYAS Security"))
        self.PYAE_Version.setText(_translate("MainWindow", "PYAE v1.2.5"))
        self.License_terms_title.setText(_translate("MainWindow", "許可條款:"))
        self.Customize_REG_Command_Back.setText(_translate("MainWindow", "返回"))
        self.Value_Path_title.setText(_translate("MainWindow", "值路徑:"))
        self.Value_Name_title.setText(_translate("MainWindow", "值名稱:"))
        self.Value_Type_title.setText(_translate("MainWindow", "值類型:"))
        self.Value_Data_title.setText(_translate("MainWindow", "值資料:"))
        self.Customize_REG_Command_Run_Button.setText(_translate("MainWindow", "確定"))
        self.Value_HEKY_title.setText(_translate("MainWindow", "值HEKY:"))
        self.Window_title.setText(_translate("MainWindow", "PYAS  V0.0.0"))
        self.Process_Tools_Back.setText(_translate("MainWindow", "返回"))
        self.Process_Total_title.setText(_translate("MainWindow", "進程總數:"))
        self.System_Process_Manage_Button.setText(_translate("MainWindow", "系統進程管理"))
        self.Repair_System_Files_Button.setText(_translate("MainWindow", "修復系統檔案"))
        self.Clean_System_Files_Button.setText(_translate("MainWindow", "清理系統檔案"))
        self.Enable_Safe_Mode_Button.setText(_translate("MainWindow", "啟動安全模式"))
        self.Disable_Safe_Mode_Button.setText(_translate("MainWindow", "關閉安全模式"))
        self.System_Info_Button.setText(_translate("MainWindow", "系統版本資訊"))
        self.System_Tools_Back.setText(_translate("MainWindow", "返回"))
        self.Analyze_EXE_Back.setText(_translate("MainWindow", "返回"))
        self.Customize_CMD_Command_Back.setText(_translate("MainWindow", "返回"))
        self.Customize_CMD_Command_Run_Button.setText(_translate("MainWindow", "運行"))
        self.Customize_CMD_Command_output_title.setText(_translate("MainWindow", "輸出(不支持中文):"))
        self.System_Tools_Button.setText(_translate("MainWindow", "系統工具"))
        self.Privacy_Tools_Button.setText(_translate("MainWindow", "隱私工具"))
        self.Develop_Tools_Button.setText(_translate("MainWindow", "開發工具"))
        self.More_Tools_Button.setText(_translate("MainWindow", "更多工具"))
        self.More_Tools_Back_Button.setText(_translate("MainWindow", "工具>"))
import PYAS_UI_rc


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
