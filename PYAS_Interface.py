from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
import sys, PYAS_Resource

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
        icon = QtGui.QIcon(QFileIconProvider().icon(QFileInfo(str(sys.argv[0]))))
        MainWindow.setWindowIcon(icon)
        MainWindow.setIconSize(QtCore.QSize(64, 64))
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
        self.Real_time_Protection_widget.setGeometry(QtCore.QRect(40, 10, 591, 91))
        self.Real_time_Protection_widget.setAcceptDrops(False)
        self.Real_time_Protection_widget.setLayoutDirection(QtCore.Qt.RightToLeft)
        self.Real_time_Protection_widget.setAutoFillBackground(False)
        self.Real_time_Protection_widget.setObjectName("Real_time_Protection_widget")
        self.Protection_title = QtWidgets.QLabel(self.Real_time_Protection_widget)
        self.Protection_title.setGeometry(QtCore.QRect(10, 10, 461, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(17)
        font.setBold(False)
        font.setWeight(50)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Protection_title.setFont(font)
        self.Protection_title.setStyleSheet("color: rgb(70,70,70);")
        self.Protection_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Protection_title.setObjectName("Protection_title")
        self.Protection_illustrate = QtWidgets.QLabel(self.Real_time_Protection_widget)
        self.Protection_illustrate.setGeometry(QtCore.QRect(10, 50, 461, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setBold(False)
        font.setWeight(50)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Protection_illustrate.setFont(font)
        self.Protection_illustrate.setStyleSheet("color: rgb(70,70,70);")
        self.Protection_illustrate.setScaledContents(False)
        self.Protection_illustrate.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Protection_illustrate.setWordWrap(True)
        self.Protection_illustrate.setObjectName("Protection_illustrate")
        self.Protection_switch_Button = QtWidgets.QPushButton(self.Real_time_Protection_widget)
        self.Protection_switch_Button.setGeometry(QtCore.QRect(490, 30, 91, 31))
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
        self.Real_time_Protection_widget_2 = QtWidgets.QWidget(self.Protection_widget)
        self.Real_time_Protection_widget_2.setGeometry(QtCore.QRect(40, 100, 591, 91))
        self.Real_time_Protection_widget_2.setAcceptDrops(False)
        self.Real_time_Protection_widget_2.setLayoutDirection(QtCore.Qt.RightToLeft)
        self.Real_time_Protection_widget_2.setAutoFillBackground(False)
        self.Real_time_Protection_widget_2.setObjectName("Real_time_Protection_widget_2")
        self.Protection_title_2 = QtWidgets.QLabel(self.Real_time_Protection_widget_2)
        self.Protection_title_2.setGeometry(QtCore.QRect(10, 10, 461, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(17)
        font.setBold(False)
        font.setWeight(50)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Protection_title_2.setFont(font)
        self.Protection_title_2.setStyleSheet("color: rgb(70,70,70);")
        self.Protection_title_2.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Protection_title_2.setObjectName("Protection_title_2")
        self.Protection_illustrate_2 = QtWidgets.QLabel(self.Real_time_Protection_widget_2)
        self.Protection_illustrate_2.setGeometry(QtCore.QRect(10, 50, 461, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setBold(False)
        font.setWeight(50)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Protection_illustrate_2.setFont(font)
        self.Protection_illustrate_2.setStyleSheet("color: rgb(70,70,70);")
        self.Protection_illustrate_2.setScaledContents(False)
        self.Protection_illustrate_2.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Protection_illustrate_2.setWordWrap(True)
        self.Protection_illustrate_2.setObjectName("Protection_illustrate_2")
        self.Protection_switch_Button_2 = QtWidgets.QPushButton(self.Real_time_Protection_widget_2)
        self.Protection_switch_Button_2.setGeometry(QtCore.QRect(490, 30, 91, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Protection_switch_Button_2.sizePolicy().hasHeightForWidth())
        self.Protection_switch_Button_2.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Protection_switch_Button_2.setFont(font)
        self.Protection_switch_Button_2.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Protection_switch_Button_2.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}")
        self.Protection_switch_Button_2.setIconSize(QtCore.QSize(16, 16))
        self.Protection_switch_Button_2.setCheckable(False)
        self.Protection_switch_Button_2.setObjectName("Protection_switch_Button_2")
        self.Real_time_Protection_widget_3 = QtWidgets.QWidget(self.Protection_widget)
        self.Real_time_Protection_widget_3.setGeometry(QtCore.QRect(40, 190, 591, 91))
        self.Real_time_Protection_widget_3.setAcceptDrops(False)
        self.Real_time_Protection_widget_3.setLayoutDirection(QtCore.Qt.RightToLeft)
        self.Real_time_Protection_widget_3.setAutoFillBackground(False)
        self.Real_time_Protection_widget_3.setObjectName("Real_time_Protection_widget_3")
        self.Protection_title_3 = QtWidgets.QLabel(self.Real_time_Protection_widget_3)
        self.Protection_title_3.setGeometry(QtCore.QRect(10, 10, 461, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(17)
        font.setBold(False)
        font.setWeight(50)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Protection_title_3.setFont(font)
        self.Protection_title_3.setStyleSheet("color: rgb(70,70,70);")
        self.Protection_title_3.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Protection_title_3.setObjectName("Protection_title_3")
        self.Protection_illustrate_3 = QtWidgets.QLabel(self.Real_time_Protection_widget_3)
        self.Protection_illustrate_3.setGeometry(QtCore.QRect(10, 50, 461, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Protection_illustrate_3.setFont(font)
        self.Protection_illustrate_3.setStyleSheet("color: rgb(70,70,70);")
        self.Protection_illustrate_3.setScaledContents(False)
        self.Protection_illustrate_3.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Protection_illustrate_3.setWordWrap(True)
        self.Protection_illustrate_3.setObjectName("Protection_illustrate_3")
        self.Protection_switch_Button_3 = QtWidgets.QPushButton(self.Real_time_Protection_widget_3)
        self.Protection_switch_Button_3.setGeometry(QtCore.QRect(490, 30, 91, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Protection_switch_Button_3.sizePolicy().hasHeightForWidth())
        self.Protection_switch_Button_3.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Protection_switch_Button_3.setFont(font)
        self.Protection_switch_Button_3.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Protection_switch_Button_3.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}")
        self.Protection_switch_Button_3.setIconSize(QtCore.QSize(16, 16))
        self.Protection_switch_Button_3.setCheckable(False)
        self.Protection_switch_Button_3.setObjectName("Protection_switch_Button_3")
        self.Real_time_Protection_widget_4 = QtWidgets.QWidget(self.Protection_widget)
        self.Real_time_Protection_widget_4.setGeometry(QtCore.QRect(40, 280, 591, 91))
        self.Real_time_Protection_widget_4.setAcceptDrops(False)
        self.Real_time_Protection_widget_4.setLayoutDirection(QtCore.Qt.RightToLeft)
        self.Real_time_Protection_widget_4.setAutoFillBackground(False)
        self.Real_time_Protection_widget_4.setObjectName("Real_time_Protection_widget_4")
        self.Protection_title_4 = QtWidgets.QLabel(self.Real_time_Protection_widget_4)
        self.Protection_title_4.setGeometry(QtCore.QRect(10, 10, 461, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(17)
        font.setBold(False)
        font.setWeight(50)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Protection_title_4.setFont(font)
        self.Protection_title_4.setStyleSheet("color: rgb(70,70,70);")
        self.Protection_title_4.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Protection_title_4.setObjectName("Protection_title_4")
        self.Protection_illustrate_4 = QtWidgets.QLabel(self.Real_time_Protection_widget_4)
        self.Protection_illustrate_4.setGeometry(QtCore.QRect(10, 50, 461, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Protection_illustrate_4.setFont(font)
        self.Protection_illustrate_4.setStyleSheet("color: rgb(70,70,70);")
        self.Protection_illustrate_4.setScaledContents(False)
        self.Protection_illustrate_4.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Protection_illustrate_4.setWordWrap(True)
        self.Protection_illustrate_4.setObjectName("Protection_illustrate_4")
        self.Protection_switch_Button_4 = QtWidgets.QPushButton(self.Real_time_Protection_widget_4)
        self.Protection_switch_Button_4.setGeometry(QtCore.QRect(490, 30, 91, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Protection_switch_Button_4.sizePolicy().hasHeightForWidth())
        self.Protection_switch_Button_4.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Protection_switch_Button_4.setFont(font)
        self.Protection_switch_Button_4.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Protection_switch_Button_4.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}")
        self.Protection_switch_Button_4.setIconSize(QtCore.QSize(16, 16))
        self.Protection_switch_Button_4.setCheckable(False)
        self.Protection_switch_Button_4.setObjectName("Protection_switch_Button_4")
        self.Real_time_Protection_widget_5 = QtWidgets.QWidget(self.Protection_widget)
        self.Real_time_Protection_widget_5.setGeometry(QtCore.QRect(40, 370, 591, 91))
        self.Real_time_Protection_widget_5.setAcceptDrops(False)
        self.Real_time_Protection_widget_5.setLayoutDirection(QtCore.Qt.RightToLeft)
        self.Real_time_Protection_widget_5.setAutoFillBackground(False)
        self.Real_time_Protection_widget_5.setObjectName("Real_time_Protection_widget_5")
        self.Protection_title_5 = QtWidgets.QLabel(self.Real_time_Protection_widget_5)
        self.Protection_title_5.setGeometry(QtCore.QRect(10, 10, 461, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(17)
        font.setBold(False)
        font.setWeight(50)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Protection_title_5.setFont(font)
        self.Protection_title_5.setStyleSheet("color: rgb(70,70,70);")
        self.Protection_title_5.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Protection_title_5.setObjectName("Protection_title_5")
        self.Protection_illustrate_5 = QtWidgets.QLabel(self.Real_time_Protection_widget_5)
        self.Protection_illustrate_5.setGeometry(QtCore.QRect(10, 50, 461, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Protection_illustrate_5.setFont(font)
        self.Protection_illustrate_5.setStyleSheet("color: rgb(70,70,70);")
        self.Protection_illustrate_5.setScaledContents(False)
        self.Protection_illustrate_5.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Protection_illustrate_5.setWordWrap(True)
        self.Protection_illustrate_5.setObjectName("Protection_illustrate_5")
        self.Protection_switch_Button_5 = QtWidgets.QPushButton(self.Real_time_Protection_widget_5)
        self.Protection_switch_Button_5.setGeometry(QtCore.QRect(490, 30, 91, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Protection_switch_Button_5.sizePolicy().hasHeightForWidth())
        self.Protection_switch_Button_5.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Protection_switch_Button_5.setFont(font)
        self.Protection_switch_Button_5.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Protection_switch_Button_5.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}")
        self.Protection_switch_Button_5.setIconSize(QtCore.QSize(16, 16))
        self.Protection_switch_Button_5.setCheckable(False)
        self.Protection_switch_Button_5.setObjectName("Protection_switch_Button_5")
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
        self.verticalLayout.setSpacing(10)
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
        font.setBold(False)
        font.setWeight(50)
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
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(":/icon/State.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.State_Button.setIcon(icon1)
        self.State_Button.setIconSize(QtCore.QSize(20, 20))
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
        font.setBold(False)
        font.setWeight(50)
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
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(":/icon/Scan.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Virus_Scan_Button.setIcon(icon2)
        self.Virus_Scan_Button.setIconSize(QtCore.QSize(20, 20))
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
        font.setBold(False)
        font.setWeight(50)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Tools_Button.setFont(font)
        self.Tools_Button.setCursor(QtGui.QCursor(QtCore.Qt.ArrowCursor))
        self.Tools_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Tools_Button.setContextMenuPolicy(QtCore.Qt.DefaultContextMenu)
        self.Tools_Button.setToolTipDuration(-7)
        self.Tools_Button.setLayoutDirection(QtCore.Qt.LeftToRight)
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
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap(":/icon/Tool.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Tools_Button.setIcon(icon3)
        self.Tools_Button.setIconSize(QtCore.QSize(20, 20))
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
        font.setBold(False)
        font.setWeight(50)
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
        icon4 = QtGui.QIcon()
        icon4.addPixmap(QtGui.QPixmap(":/icon/Protect.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Protection_Button.setIcon(icon4)
        self.Protection_Button.setIconSize(QtCore.QSize(20, 20))
        self.Protection_Button.setCheckable(False)
        self.Protection_Button.setObjectName("Protection_Button")
        self.verticalLayout.addWidget(self.Protection_Button)
        self.label = QtWidgets.QPushButton(self.Navigation_Bar)
        self.label.setEnabled(False)
        self.label.setGeometry(QtCore.QRect(20, 50, 5, 30))
        self.label.setMouseTracking(False)
        self.label.setAutoFillBackground(False)
        self.label.setStyleSheet("QPushButton#label\n"
"{\n"
"    background-color:rgba(255,255,255,255);\n"
"    border-radius: 2px;\n"
"}")
        self.label.setText("")
        self.label.setCheckable(False)
        self.label.setAutoRepeatDelay(300)
        self.label.setAutoRepeatInterval(100)
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
        self.Virus_Scan_title.setGeometry(QtCore.QRect(45, 30, 281, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(17)
        font.setBold(False)
        font.setWeight(50)
        self.Virus_Scan_title.setFont(font)
        self.Virus_Scan_title.setStyleSheet("color: rgb(70,70,70);")
        self.Virus_Scan_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Virus_Scan_title.setObjectName("Virus_Scan_title")
        self.Virus_Scan_text = QtWidgets.QLabel(self.Virus_Scan_widget)
        self.Virus_Scan_text.setGeometry(QtCore.QRect(45, 70, 581, 71))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        self.Virus_Scan_text.setFont(font)
        self.Virus_Scan_text.setStyleSheet("color: rgb(70,70,70);")
        self.Virus_Scan_text.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Virus_Scan_text.setWordWrap(True)
        self.Virus_Scan_text.setObjectName("Virus_Scan_text")
        self.Virus_Scan_choose_Button = QtWidgets.QPushButton(self.Virus_Scan_widget)
        self.Virus_Scan_choose_Button.setGeometry(QtCore.QRect(480, 35, 141, 31))
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
        self.Virus_Scan_choose_Button.setIconSize(QtCore.QSize(10, 10))
        self.Virus_Scan_choose_Button.setCheckable(False)
        self.Virus_Scan_choose_Button.setAutoRepeat(False)
        self.Virus_Scan_choose_Button.setAutoExclusive(False)
        self.Virus_Scan_choose_Button.setAutoRepeatDelay(300)
        self.Virus_Scan_choose_Button.setAutoRepeatInterval(100)
        self.Virus_Scan_choose_Button.setDefault(False)
        self.Virus_Scan_choose_Button.setFlat(False)
        self.Virus_Scan_choose_Button.setObjectName("Virus_Scan_choose_Button")
        self.Virus_Scan_choose_widget = QtWidgets.QWidget(self.Virus_Scan_widget)
        self.Virus_Scan_choose_widget.setGeometry(QtCore.QRect(480, 67, 141, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Virus_Scan_choose_widget.sizePolicy().hasHeightForWidth())
        self.Virus_Scan_choose_widget.setSizePolicy(sizePolicy)
        self.Virus_Scan_choose_widget.setStyleSheet("background-color:rgba(200, 200, 200,200);")
        self.Virus_Scan_choose_widget.setObjectName("Virus_Scan_choose_widget")
        self.verticalLayoutWidget_3 = QtWidgets.QWidget(self.Virus_Scan_choose_widget)
        self.verticalLayoutWidget_3.setGeometry(QtCore.QRect(0, 0, 141, 101))
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
        self.Virus_Scan_Solve_Button.setGeometry(QtCore.QRect(330, 35, 141, 31))
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
        self.Virus_Scan_Break_Button.setGeometry(QtCore.QRect(480, 35, 141, 31))
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
        self.Virus_Scan_output = QtWidgets.QListWidget(self.Virus_Scan_widget)
        self.Virus_Scan_output.setGeometry(QtCore.QRect(45, 150, 581, 301))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(9)
        self.Virus_Scan_output.setFont(font)
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
        self.Virus_Scan_output.setTabKeyNavigation(False)
        self.Virus_Scan_output.setProperty("showDropIndicator", True)
        self.Virus_Scan_output.setDefaultDropAction(QtCore.Qt.CopyAction)
        self.Virus_Scan_output.setAlternatingRowColors(False)
        self.Virus_Scan_output.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.Virus_Scan_output.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectItems)
        self.Virus_Scan_output.setVerticalScrollMode(QtWidgets.QAbstractItemView.ScrollPerItem)
        self.Virus_Scan_output.setHorizontalScrollMode(QtWidgets.QAbstractItemView.ScrollPerItem)
        self.Virus_Scan_output.setMovement(QtWidgets.QListView.Static)
        self.Virus_Scan_output.setProperty("isWrapping", False)
        self.Virus_Scan_output.setResizeMode(QtWidgets.QListView.Fixed)
        self.Virus_Scan_output.setLayoutMode(QtWidgets.QListView.SinglePass)
        self.Virus_Scan_output.setViewMode(QtWidgets.QListView.ListMode)
        self.Virus_Scan_output.setUniformItemSizes(False)
        self.Virus_Scan_output.setSelectionRectVisible(False)
        self.Virus_Scan_output.setObjectName("Virus_Scan_output")
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
        self.State_title.setGeometry(QtCore.QRect(50, 210, 571, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(15)
        font.setBold(True)
        font.setWeight(75)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.State_title.setFont(font)
        self.State_title.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.State_title.setStyleSheet("")
        self.State_title.setAlignment(QtCore.Qt.AlignCenter)
        self.State_title.setObjectName("State_title")
        self.State_icon = QtWidgets.QLabel(self.State_widget)
        self.State_icon.setGeometry(QtCore.QRect(250, 30, 171, 171))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(1)
        font.setKerning(True)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.State_icon.setFont(font)
        self.State_icon.setContextMenuPolicy(QtCore.Qt.DefaultContextMenu)
        self.State_icon.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.State_icon.setLineWidth(1)
        self.State_icon.setText("")
        self.State_icon.setTextFormat(QtCore.Qt.AutoText)
        self.State_icon.setPixmap(QtGui.QPixmap(":/icon/Check.png"))
        self.State_icon.setScaledContents(True)
        self.State_icon.setAlignment(QtCore.Qt.AlignCenter)
        self.State_icon.setObjectName("State_icon")
        self.State_output = QtWidgets.QTextEdit(self.State_widget)
        self.State_output.setGeometry(QtCore.QRect(50, 300, 571, 151))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        font.setStrikeOut(False)
        font.setKerning(True)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.State_output.setFont(font)
        self.State_output.setAutoFillBackground(False)
        self.State_output.setStyleSheet("")
        self.State_output.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustIgnored)
        self.State_output.setUndoRedoEnabled(True)
        self.State_output.setTextInteractionFlags(QtCore.Qt.TextSelectableByKeyboard|QtCore.Qt.TextSelectableByMouse)
        self.State_output.setObjectName("State_output")
        self.State_log = QtWidgets.QLabel(self.State_widget)
        self.State_log.setGeometry(QtCore.QRect(50, 260, 571, 31))
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
        self.About_Back.setGeometry(QtCore.QRect(20, 10, 101, 41))
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
        icon5 = QtGui.QIcon()
        icon5.addPixmap(QtGui.QPixmap(":/icon/Back.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.About_Back.setIcon(icon5)
        self.About_Back.setIconSize(QtCore.QSize(20, 20))
        self.About_Back.setCheckable(False)
        self.About_Back.setObjectName("About_Back")
        self.PYAS_Version = QtWidgets.QLabel(self.About_widget)
        self.PYAS_Version.setGeometry(QtCore.QRect(45, 50, 571, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(15)
        font.setBold(False)
        font.setUnderline(False)
        font.setWeight(50)
        self.PYAS_Version.setFont(font)
        self.PYAS_Version.setStyleSheet("")
        self.PYAS_Version.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.PYAS_Version.setObjectName("PYAS_Version")
        self.GUI_Made_title = QtWidgets.QLabel(self.About_widget)
        self.GUI_Made_title.setGeometry(QtCore.QRect(45, 100, 131, 31))
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
        self.GUI_Made_Name.setGeometry(QtCore.QRect(185, 100, 441, 31))
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
        self.Core_Made_title.setGeometry(QtCore.QRect(45, 140, 131, 31))
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
        self.Core_Made_Name.setGeometry(QtCore.QRect(185, 140, 441, 31))
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
        self.Testers_title.setGeometry(QtCore.QRect(45, 180, 131, 31))
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
        self.Testers_Name.setGeometry(QtCore.QRect(185, 180, 441, 31))
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
        self.PYAS_URL_title.setGeometry(QtCore.QRect(45, 220, 131, 31))
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
        self.PYAS_URL.setGeometry(QtCore.QRect(185, 220, 441, 31))
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
        self.PYAS_CopyRight.setGeometry(QtCore.QRect(45, 430, 581, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setBold(False)
        font.setWeight(50)
        self.PYAS_CopyRight.setFont(font)
        self.PYAS_CopyRight.setStyleSheet("")
        self.PYAS_CopyRight.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.PYAS_CopyRight.setObjectName("PYAS_CopyRight")
        self.License_terms = QtWidgets.QTextEdit(self.About_widget)
        self.License_terms.setGeometry(QtCore.QRect(45, 300, 581, 131))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.License_terms.setFont(font)
        self.License_terms.setStyleSheet("")
        self.License_terms.setReadOnly(True)
        self.License_terms.setObjectName("License_terms")
        self.License_terms_title = QtWidgets.QLabel(self.About_widget)
        self.License_terms_title.setGeometry(QtCore.QRect(45, 260, 581, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setBold(False)
        font.setWeight(50)
        self.License_terms_title.setFont(font)
        self.License_terms_title.setStyleSheet("")
        self.License_terms_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.License_terms_title.setObjectName("License_terms_title")
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
        icon6 = QtGui.QIcon()
        icon6.addPixmap(QtGui.QPixmap(":/icon/Close.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Close_Button.setIcon(icon6)
        self.Close_Button.setIconSize(QtCore.QSize(16, 16))
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
        icon7 = QtGui.QIcon()
        icon7.addPixmap(QtGui.QPixmap(":/icon/Minimize.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Minimize_Button.setIcon(icon7)
        self.Minimize_Button.setIconSize(QtCore.QSize(16, 16))
        self.Minimize_Button.setCheckable(False)
        self.Minimize_Button.setObjectName("Minimize_Button")
        self.Window_title = QtWidgets.QLabel(self.Window_widget)
        self.Window_title.setGeometry(QtCore.QRect(10, 0, 691, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(15)
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
        icon8 = QtGui.QIcon()
        icon8.addPixmap(QtGui.QPixmap(":/icon/Menu.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Menu_Button.setIcon(icon8)
        self.Menu_Button.setIconSize(QtCore.QSize(16, 16))
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
        self.Process_Tools_Back.setGeometry(QtCore.QRect(20, 10, 101, 41))
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
        self.Process_Tools_Back.setIcon(icon5)
        self.Process_Tools_Back.setIconSize(QtCore.QSize(20, 20))
        self.Process_Tools_Back.setCheckable(False)
        self.Process_Tools_Back.setObjectName("Process_Tools_Back")
        self.Process_list = QtWidgets.QListView(self.Process_widget)
        self.Process_list.setGeometry(QtCore.QRect(40, 60, 591, 361))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(9)
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
        self.Process_Total_title.setGeometry(QtCore.QRect(40, 425, 131, 41))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setBold(False)
        font.setWeight(50)
        self.Process_Total_title.setFont(font)
        self.Process_Total_title.setStyleSheet("")
        self.Process_Total_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Process_Total_title.setObjectName("Process_Total_title")
        self.Process_Total_View = QtWidgets.QLineEdit(self.Process_widget)
        self.Process_Total_View.setGeometry(QtCore.QRect(180, 430, 451, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Process_Total_View.setFont(font)
        self.Process_Total_View.setText("")
        self.Process_Total_View.setReadOnly(True)
        self.Process_Total_View.setObjectName("Process_Total_View")
        self.Tools_widget = QtWidgets.QWidget(self.widget)
        self.Tools_widget.setGeometry(QtCore.QRect(170, 50, 671, 481))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Tools_widget.setFont(font)
        self.Tools_widget.setStyleSheet("background-color:rgba(255, 255, 255,240);")
        self.Tools_widget.setObjectName("Tools_widget")
        self.More_Tools_Back_Button = QtWidgets.QPushButton(self.Tools_widget)
        self.More_Tools_Back_Button.setGeometry(QtCore.QRect(20, 10, 101, 41))
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
        self.verticalLayoutWidget_4 = QtWidgets.QWidget(self.Tools_widget)
        self.verticalLayoutWidget_4.setGeometry(QtCore.QRect(30, 50, 611, 411))
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
        font.setPointSize(13)
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
        self.Clean_System_Files_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_4)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Clean_System_Files_Button.sizePolicy().hasHeightForWidth())
        self.Clean_System_Files_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
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
        self.Repair_System_Files_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_4)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Repair_System_Files_Button.sizePolicy().hasHeightForWidth())
        self.Repair_System_Files_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
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
        self.Repair_System_Network_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_4)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Repair_System_Network_Button.sizePolicy().hasHeightForWidth())
        self.Repair_System_Network_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Repair_System_Network_Button.setFont(font)
        self.Repair_System_Network_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Repair_System_Network_Button.setStyleSheet("QPushButton\n"
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
        self.Repair_System_Network_Button.setIconSize(QtCore.QSize(16, 16))
        self.Repair_System_Network_Button.setCheckable(False)
        self.Repair_System_Network_Button.setObjectName("Repair_System_Network_Button")
        self.System_verticalLayout.addWidget(self.Repair_System_Network_Button)
        self.Window_Block_Button = QtWidgets.QPushButton(self.verticalLayoutWidget_4)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Window_Block_Button.sizePolicy().hasHeightForWidth())
        self.Window_Block_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(13)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Window_Block_Button.setFont(font)
        self.Window_Block_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Window_Block_Button.setStyleSheet("QPushButton\n"
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
        self.Window_Block_Button.setIconSize(QtCore.QSize(16, 16))
        self.Window_Block_Button.setCheckable(False)
        self.Window_Block_Button.setObjectName("Window_Block_Button")
        self.System_verticalLayout.addWidget(self.Window_Block_Button)
        self.widget_2 = QtWidgets.QWidget(self.widget)
        self.widget_2.setGeometry(QtCore.QRect(170, 50, 671, 481))
        self.widget_2.setStyleSheet("background-color:rgb(255, 255, 255);")
        self.widget_2.setObjectName("widget_2")
        self.Setting_widget = QtWidgets.QWidget(self.widget)
        self.Setting_widget.setGeometry(QtCore.QRect(10, 50, 831, 481))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Setting_widget.setFont(font)
        self.Setting_widget.setStyleSheet("background-color:rgba(255, 255, 255,255);")
        self.Setting_widget.setObjectName("Setting_widget")
        self.Show_high_sensitivity = QtWidgets.QWidget(self.Setting_widget)
        self.Show_high_sensitivity.setGeometry(QtCore.QRect(30, 50, 781, 81))
        self.Show_high_sensitivity.setAcceptDrops(False)
        self.Show_high_sensitivity.setAutoFillBackground(False)
        self.Show_high_sensitivity.setObjectName("Show_high_sensitivity")
        self.high_sensitivity_title = QtWidgets.QLabel(self.Show_high_sensitivity)
        self.high_sensitivity_title.setGeometry(QtCore.QRect(20, 10, 451, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(17)
        font.setBold(False)
        font.setWeight(50)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.high_sensitivity_title.setFont(font)
        self.high_sensitivity_title.setStyleSheet("color: rgb(70,70,70);")
        self.high_sensitivity_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.high_sensitivity_title.setObjectName("high_sensitivity_title")
        self.high_sensitivity_illustrate = QtWidgets.QLabel(self.Show_high_sensitivity)
        self.high_sensitivity_illustrate.setGeometry(QtCore.QRect(20, 40, 451, 31))
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
        self.high_sensitivity_switch_Button.setGeometry(QtCore.QRect(660, 20, 91, 31))
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
        self.high_sensitivity_illustrate.raise_()
        self.high_sensitivity_switch_Button.raise_()
        self.high_sensitivity_title.raise_()
        self.Llanguage_widget = QtWidgets.QWidget(self.Setting_widget)
        self.Llanguage_widget.setGeometry(QtCore.QRect(30, 370, 781, 81))
        self.Llanguage_widget.setAcceptDrops(False)
        self.Llanguage_widget.setAutoFillBackground(False)
        self.Llanguage_widget.setObjectName("Llanguage_widget")
        self.Language_title = QtWidgets.QLabel(self.Llanguage_widget)
        self.Language_title.setGeometry(QtCore.QRect(20, 10, 361, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(17)
        font.setBold(False)
        font.setWeight(50)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Language_title.setFont(font)
        self.Language_title.setStyleSheet("color: rgb(70,70,70);")
        self.Language_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Language_title.setObjectName("Language_title")
        self.Language_illustrate = QtWidgets.QLabel(self.Llanguage_widget)
        self.Language_illustrate.setGeometry(QtCore.QRect(20, 40, 361, 31))
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
        self.Language_Choose_widget.setGeometry(QtCore.QRect(400, 10, 381, 61))
        font = QtGui.QFont()
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Language_Choose_widget.setFont(font)
        self.Language_Choose_widget.setObjectName("Language_Choose_widget")
        self.gridLayoutWidget = QtWidgets.QWidget(self.Language_Choose_widget)
        self.gridLayoutWidget.setGeometry(QtCore.QRect(0, 0, 381, 61))
        self.gridLayoutWidget.setObjectName("gridLayoutWidget")
        self.gridLayout = QtWidgets.QGridLayout(self.gridLayoutWidget)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.gridLayout.setObjectName("gridLayout")
        self.Language_Traditional_Chinese = QtWidgets.QRadioButton(self.gridLayoutWidget)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Language_Traditional_Chinese.setFont(font)
        self.Language_Traditional_Chinese.setObjectName("Language_Traditional_Chinese")
        self.gridLayout.addWidget(self.Language_Traditional_Chinese, 1, 0, 1, 1)
        self.Language_Simplified_Chinese = QtWidgets.QRadioButton(self.gridLayoutWidget)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Language_Simplified_Chinese.setFont(font)
        self.Language_Simplified_Chinese.setObjectName("Language_Simplified_Chinese")
        self.gridLayout.addWidget(self.Language_Simplified_Chinese, 1, 1, 1, 1)
        self.Language_English = QtWidgets.QRadioButton(self.gridLayoutWidget)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Language_English.setFont(font)
        self.Language_English.setObjectName("Language_English")
        self.gridLayout.addWidget(self.Language_English, 1, 2, 1, 1)
        self.Language_illustrate.raise_()
        self.Language_Choose_widget.raise_()
        self.Language_title.raise_()
        self.Show_cloud_services = QtWidgets.QWidget(self.Setting_widget)
        self.Show_cloud_services.setGeometry(QtCore.QRect(30, 130, 781, 81))
        self.Show_cloud_services.setAcceptDrops(False)
        self.Show_cloud_services.setAutoFillBackground(False)
        self.Show_cloud_services.setObjectName("Show_cloud_services")
        self.cloud_services_title = QtWidgets.QLabel(self.Show_cloud_services)
        self.cloud_services_title.setGeometry(QtCore.QRect(20, 10, 451, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(17)
        font.setBold(False)
        font.setWeight(50)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.cloud_services_title.setFont(font)
        self.cloud_services_title.setStyleSheet("color: rgb(70,70,70);")
        self.cloud_services_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.cloud_services_title.setObjectName("cloud_services_title")
        self.cloud_services_illustrate = QtWidgets.QLabel(self.Show_cloud_services)
        self.cloud_services_illustrate.setGeometry(QtCore.QRect(20, 40, 451, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.cloud_services_illustrate.setFont(font)
        self.cloud_services_illustrate.setStyleSheet("color: rgb(70,70,70);")
        self.cloud_services_illustrate.setScaledContents(False)
        self.cloud_services_illustrate.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.cloud_services_illustrate.setWordWrap(True)
        self.cloud_services_illustrate.setObjectName("cloud_services_illustrate")
        self.cloud_services_switch_Button = QtWidgets.QPushButton(self.Show_cloud_services)
        self.cloud_services_switch_Button.setGeometry(QtCore.QRect(660, 20, 91, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.cloud_services_switch_Button.sizePolicy().hasHeightForWidth())
        self.cloud_services_switch_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.cloud_services_switch_Button.setFont(font)
        self.cloud_services_switch_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.cloud_services_switch_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}")
        self.cloud_services_switch_Button.setIconSize(QtCore.QSize(16, 16))
        self.cloud_services_switch_Button.setCheckable(False)
        self.cloud_services_switch_Button.setObjectName("cloud_services_switch_Button")
        self.cloud_services_illustrate.raise_()
        self.cloud_services_switch_Button.raise_()
        self.cloud_services_title.raise_()
        self.Setting_Back = QtWidgets.QPushButton(self.Setting_widget)
        self.Setting_Back.setGeometry(QtCore.QRect(25, 10, 101, 41))
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
        self.Setting_Back.setIcon(icon5)
        self.Setting_Back.setIconSize(QtCore.QSize(20, 20))
        self.Setting_Back.setCheckable(False)
        self.Setting_Back.setObjectName("Setting_Back")
        self.Add_White_list = QtWidgets.QWidget(self.Setting_widget)
        self.Add_White_list.setGeometry(QtCore.QRect(30, 210, 781, 81))
        self.Add_White_list.setAcceptDrops(False)
        self.Add_White_list.setAutoFillBackground(False)
        self.Add_White_list.setObjectName("Add_White_list")
        self.Add_White_list_title = QtWidgets.QLabel(self.Add_White_list)
        self.Add_White_list_title.setGeometry(QtCore.QRect(20, 10, 451, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(17)
        font.setBold(False)
        font.setWeight(50)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Add_White_list_title.setFont(font)
        self.Add_White_list_title.setStyleSheet("color: rgb(70,70,70);")
        self.Add_White_list_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Add_White_list_title.setObjectName("Add_White_list_title")
        self.Add_White_list_illustrate = QtWidgets.QLabel(self.Add_White_list)
        self.Add_White_list_illustrate.setGeometry(QtCore.QRect(20, 40, 451, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Add_White_list_illustrate.setFont(font)
        self.Add_White_list_illustrate.setStyleSheet("color: rgb(70,70,70);")
        self.Add_White_list_illustrate.setScaledContents(False)
        self.Add_White_list_illustrate.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Add_White_list_illustrate.setWordWrap(True)
        self.Add_White_list_illustrate.setObjectName("Add_White_list_illustrate")
        self.Add_White_list_Button = QtWidgets.QPushButton(self.Add_White_list)
        self.Add_White_list_Button.setGeometry(QtCore.QRect(660, 20, 91, 31))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Add_White_list_Button.sizePolicy().hasHeightForWidth())
        self.Add_White_list_Button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Add_White_list_Button.setFont(font)
        self.Add_White_list_Button.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.Add_White_list_Button.setStyleSheet("QPushButton\n"
"{\n"
"    border:none;\n"
"    background-color:rgba(20,20,20,30);\n"
"    border-radius: 15px;\n"
"}\n"
"QPushButton:hover\n"
"{\n"
"    background-color:rgba(20,20,20,50);\n"
"}")
        self.Add_White_list_Button.setIconSize(QtCore.QSize(16, 16))
        self.Add_White_list_Button.setCheckable(False)
        self.Add_White_list_Button.setObjectName("Add_White_list_Button")
        self.Add_White_list_illustrate.raise_()
        self.Add_White_list_Button.raise_()
        self.Add_White_list_title.raise_()
        self.Theme_widget = QtWidgets.QWidget(self.Setting_widget)
        self.Theme_widget.setGeometry(QtCore.QRect(30, 290, 781, 81))
        self.Theme_widget.setObjectName("Theme_widget")
        self.Theme_title = QtWidgets.QLabel(self.Theme_widget)
        self.Theme_title.setGeometry(QtCore.QRect(20, 10, 351, 31))
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(17)
        font.setBold(False)
        font.setWeight(50)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Theme_title.setFont(font)
        self.Theme_title.setStyleSheet("color: rgb(70,70,70);")
        self.Theme_title.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.Theme_title.setObjectName("Theme_title")
        self.Theme_illustrate = QtWidgets.QLabel(self.Theme_widget)
        self.Theme_illustrate.setGeometry(QtCore.QRect(20, 40, 351, 31))
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
        self.Language_Choose_widget_2.setGeometry(QtCore.QRect(400, 10, 381, 61))
        font = QtGui.QFont()
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Language_Choose_widget_2.setFont(font)
        self.Language_Choose_widget_2.setObjectName("Language_Choose_widget_2")
        self.gridLayoutWidget_2 = QtWidgets.QWidget(self.Language_Choose_widget_2)
        self.gridLayoutWidget_2.setGeometry(QtCore.QRect(0, 0, 381, 65))
        self.gridLayoutWidget_2.setObjectName("gridLayoutWidget_2")
        self.gridLayout_2 = QtWidgets.QGridLayout(self.gridLayoutWidget_2)
        self.gridLayout_2.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.Theme_Black = QtWidgets.QRadioButton(self.gridLayoutWidget_2)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Theme_Black.setFont(font)
        self.Theme_Black.setObjectName("Theme_Black")
        self.gridLayout_2.addWidget(self.Theme_Black, 1, 1, 1, 1)
        self.Theme_White = QtWidgets.QRadioButton(self.gridLayoutWidget_2)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Theme_White.setFont(font)
        self.Theme_White.setObjectName("Theme_White")
        self.gridLayout_2.addWidget(self.Theme_White, 1, 0, 1, 1)
        self.Theme_Yellow = QtWidgets.QRadioButton(self.gridLayoutWidget_2)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Theme_Yellow.setFont(font)
        self.Theme_Yellow.setObjectName("Theme_Yellow")
        self.gridLayout_2.addWidget(self.Theme_Yellow, 1, 2, 1, 1)
        self.Theme_Blue = QtWidgets.QRadioButton(self.gridLayoutWidget_2)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        self.Theme_Blue.setFont(font)
        self.Theme_Blue.setObjectName("Theme_Blue")
        self.gridLayout_2.addWidget(self.Theme_Blue, 2, 0, 1, 1)
        self.Theme_Red = QtWidgets.QRadioButton(self.gridLayoutWidget_2)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Theme_Red.setFont(font)
        self.Theme_Red.setObjectName("Theme_Red")
        self.gridLayout_2.addWidget(self.Theme_Red, 2, 1, 1, 1)
        self.Theme_Green = QtWidgets.QRadioButton(self.gridLayoutWidget_2)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei")
        font.setPointSize(11)
        font.setStyleStrategy(QtGui.QFont.PreferAntialias)
        self.Theme_Green.setFont(font)
        self.Theme_Green.setObjectName("Theme_Green")
        self.gridLayout_2.addWidget(self.Theme_Green, 2, 2, 1, 1)
        self.Theme_illustrate.raise_()
        self.Language_Choose_widget_2.raise_()
        self.Theme_title.raise_()
        self.Protection_widget.raise_()
        self.Setting_widget.raise_()
        self.About_widget.raise_()
        self.Tools_widget.raise_()
        self.widget_2.raise_()
        self.Process_widget.raise_()
        self.Virus_Scan_widget.raise_()
        self.Window_widget.raise_()
        self.Navigation_Bar.raise_()
        self.State_widget.raise_()
        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "PYAS"))
        self.Protection_title.setText(_translate("MainWindow", "進程防護"))
        self.Protection_illustrate.setText(_translate("MainWindow", "啟用該選項可以實時監控進程中的惡意軟體並清除"))
        self.Protection_switch_Button.setText(_translate("MainWindow", "已關閉"))
        self.Protection_title_2.setText(_translate("MainWindow", "進程防護"))
        self.Protection_illustrate_2.setText(_translate("MainWindow", "啟用該選項可以實時監控進程中的惡意軟體並清除"))
        self.Protection_switch_Button_2.setText(_translate("MainWindow", "已關閉"))
        self.Protection_title_3.setText(_translate("MainWindow", "進程防護"))
        self.Protection_illustrate_3.setText(_translate("MainWindow", "啟用該選項可以實時監控進程中的惡意軟體並清除"))
        self.Protection_switch_Button_3.setText(_translate("MainWindow", "已關閉"))
        self.Protection_title_4.setText(_translate("MainWindow", "進程防護"))
        self.Protection_illustrate_4.setText(_translate("MainWindow", "啟用該選項可以實時監控進程中的惡意軟體並清除"))
        self.Protection_switch_Button_4.setText(_translate("MainWindow", "已關閉"))
        self.Protection_title_5.setText(_translate("MainWindow", "進程防護"))
        self.Protection_illustrate_5.setText(_translate("MainWindow", "啟用該選項可以實時監控進程中的惡意軟體並清除"))
        self.Protection_switch_Button_5.setText(_translate("MainWindow", "已關閉"))
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
        self.Virus_Scan_output.setSortingEnabled(False)
        self.State_title.setText(_translate("MainWindow", "This Device Has Been Protect"))
        self.State_output.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'Microsoft YaHei\'; font-size:11pt; font-weight:400; font-style:normal;\">\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p></body></html>"))
        self.State_log.setText(_translate("MainWindow", "日誌:"))
        self.About_Back.setText(_translate("MainWindow", "返回"))
        self.PYAS_Version.setText(_translate("MainWindow", "PYAS  v2.3.5"))
        self.GUI_Made_title.setText(_translate("MainWindow", "介面製作:"))
        self.GUI_Made_Name.setText(_translate("MainWindow", "mtkiao129#3921"))
        self.Core_Made_title.setText(_translate("MainWindow", "核心製作:"))
        self.Core_Made_Name.setText(_translate("MainWindow", "PYAS_Dev#0629"))
        self.Testers_title.setText(_translate("MainWindow", "測試人員:"))
        self.Testers_Name.setText(_translate("MainWindow", "PYAS_Dev#0629"))
        self.PYAS_URL_title.setText(_translate("MainWindow", "官方網站:"))
        self.PYAS_URL.setText(_translate("MainWindow", "<html><head/><body><p><a href=\"https://xiaomi69ai.wixsite.com/pyas\"><span style=\" text-decoration: underline; color:#0000ff;\">https://xiaomi69ai.wixsite.com/pyas</span></a></p></body></html>"))
        self.PYAS_CopyRight.setText(_translate("MainWindow", "Copyright© 2020-2022 PYAS Security"))
        self.License_terms_title.setText(_translate("MainWindow", "許可條款:"))
        self.Window_title.setText(_translate("MainWindow", "PYAS  V0.0.0"))
        self.Process_Tools_Back.setText(_translate("MainWindow", "返回"))
        self.Process_Total_title.setText(_translate("MainWindow", "進程總數:"))
        self.More_Tools_Back_Button.setText(_translate("MainWindow", "工具>"))
        self.System_Process_Manage_Button.setText(_translate("MainWindow", "系統進程管理"))
        self.Clean_System_Files_Button.setText(_translate("MainWindow", "清理系統檔案"))
        self.Repair_System_Files_Button.setText(_translate("MainWindow", "修復系統檔案"))
        self.Repair_System_Network_Button.setText(_translate("MainWindow", "修復系統網路"))
        self.Window_Block_Button.setText(_translate("MainWindow", "軟體彈窗攔截"))
        self.high_sensitivity_title.setText(_translate("MainWindow", "高靈敏度模式"))
        self.high_sensitivity_illustrate.setText(_translate("MainWindow", "啟用此選項可以提高引擎的靈敏度"))
        self.high_sensitivity_switch_Button.setText(_translate("MainWindow", "已關閉"))
        self.Language_title.setText(_translate("MainWindow", "語言"))
        self.Language_illustrate.setText(_translate("MainWindow", "請選擇語言"))
        self.Language_Traditional_Chinese.setText(_translate("MainWindow", "繁體中文"))
        self.Language_Simplified_Chinese.setText(_translate("MainWindow", "简体中文"))
        self.Language_English.setText(_translate("MainWindow", "English"))
        self.cloud_services_title.setText(_translate("MainWindow", "高靈敏度模式"))
        self.cloud_services_illustrate.setText(_translate("MainWindow", "啟用此選項可以提高引擎的靈敏度"))
        self.cloud_services_switch_Button.setText(_translate("MainWindow", "已關閉"))
        self.Setting_Back.setText(_translate("MainWindow", "返回"))
        self.Add_White_list_title.setText(_translate("MainWindow", "高靈敏度模式"))
        self.Add_White_list_illustrate.setText(_translate("MainWindow", "啟用此選項可以提高引擎的靈敏度"))
        self.Add_White_list_Button.setText(_translate("MainWindow", "已關閉"))
        self.Theme_title.setText(_translate("MainWindow", "顯色主題"))
        self.Theme_illustrate.setText(_translate("MainWindow", "請選擇主題"))
        self.Theme_Black.setText(_translate("MainWindow", "黑色主題"))
        self.Theme_White.setText(_translate("MainWindow", "白色主題"))
        self.Theme_Yellow.setText(_translate("MainWindow", "粉色主題"))
        self.Theme_Blue.setText(_translate("MainWindow", "藍色主題"))
        self.Theme_Red.setText(_translate("MainWindow", "紅色主題"))
        self.Theme_Green.setText(_translate("MainWindow", "綠色主題"))

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
