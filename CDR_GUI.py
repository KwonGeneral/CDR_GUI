import subprocess
import time

import hexdump
import requests
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
import os
import sys
import struct
import codecs
import hashlib
import oleparser
import icon
import itertools
from winreg import *


# =============================== 레지스트리 ===============================
def Reg_Change():
    os.system("mkdir c:\CDR")
    os.system("copy cdr c:\CDR")
    os.system("ren C:\CDR\cdr cdr.exe")
    root_handle = ConnectRegistry(None, HKEY_CLASSES_ROOT)

    read_key = OpenKey(root_handle, ".hwp", 0, KEY_READ)

    for i in itertools.count():
        try:
            name = EnumKey(read_key, i)
            # if '.hwp' in name:
            if 'OpenWithProgids' in name:
                hwp_name = name.rstrip()
                ad = str(EnumValue(read_key, 0))
                ca = ad.strip('(').strip(')').rstrip("', 1").lstrip("'', '")
            else:
                pass
        except WindowsError:
            break
    hwp_location = ca + '\shell\open\command'

    write_key = OpenKey(root_handle, hwp_location, 0, KEY_WRITE)

    SetValue(write_key, "", REG_SZ, '"C:\CDR\cdr.bat" "%1"')

    default = ca + "\DefaultIcon"
    default_key = OpenKey(root_handle, default, 0, KEY_READ)
    de = EnumValue(default_key, 0)
    kk = str(de)
    kk.replace('hwpviewer.exe', 'HwpViewer.exe')

    d = open('C:\CDR\hwp.lot', 'w')
    d.write(kk)

    CloseKey(read_key)
    CloseKey(write_key)

    f = open('C:\CDR\cdr.bat', 'w')
    data = '@echo off\nstart C:\CDR\cdr.exe "%*"\necho %* >  C:\CDR\cdr.list\nexit'
    f.write(data)
    f.close()


def Reg_Recover():
    root_handle = ConnectRegistry(None, HKEY_CLASSES_ROOT)

    read_key = OpenKey(root_handle, ".hwp", 0, KEY_READ)

    for i in itertools.count():
        try:
            name = EnumKey(read_key, i)
            # if '.hwp' in name:
            if 'OpenWithProgids' in name:
                hwp_name = name.rstrip()
                ad = str(EnumValue(read_key, 0))
                ca = ad.strip('(').strip(')').rstrip("', 1").lstrip("'', '")
            else:
                pass
        except WindowsError:
            break
    hwp_location = ca + '\shell\open\command'
    write_key = OpenKey(root_handle, hwp_location, 0, KEY_WRITE)
    default = ca + "\DefaultIcon"
    default_key = OpenKey(root_handle, default, 0, KEY_READ)
    de = EnumValue(default_key, 0)
    kk = str(de)
    kk.replace('hwpviewer.exe', 'HwpViewer.exe')

    x = kk
    g = x.strip('(').strip(')').strip("'', ").rstrip(",1', 1") + ' '
    g += '"%1"'
    # "C:\Program Files (x86)\Hnc\Office 2020\HOffice110\bin\Hwp.exe" "%1"

    SetValueEx(write_key, "", 0, REG_SZ, g)

    CloseKey(read_key)
    CloseKey(write_key)

# =============================== 암복호화 ===============================


# =============================== GUI ===============================
style = """
QMenuBar {
    spacing: 1px;           
    padding: 2px -1px;
    background-color: white;
    border-style: solid;
    border-width: 1px;
    border-color: #848484;
    border-bottom-style: ridge;
    border-bottom-width: 2px;
    border-right-width: 0px;
    border-left-width: 0px;
}
QMenuBar::item {
    spacing: 3px;           
    padding: 3px 12px;
    background-color: #FAFAFA;
    color: black; 
}
QMenuBar::item:selected {    
    background-color: rgb(244,164,96);
    color: black;
}
QMenuBar::item:pressed {
    background: rgb(244,164,96);
}

QMenu {
    spacing: 3px;           
    padding: 2px 10px;
    background-color: white;
    color: white;
}
QMenu::item {
    background-color: white;
    color: #120A2A; 
}
QMenu::item:selected { 
    background-color: rgb(244,164,96);
    color: #2E2E2E;
}

Qtextedit{
    font-family: Arial;    
}

QHeaderView::section {
    color : white;
    background-color:#5390d9;
    font : 맑은 고딕 9pt;
    font-weight: bold;
}

QHeaderView::section {
    color : white;
    background-color:#5390d9;
    font : 맑은 고딕 9pt;
    font-weight: bold;
}

QTableWidget::item::selected {
    color : white;
    background-color:#5390d9;
    font : 맑은 고딕 9pt;
    font-weight: bold;
}

QTabBar::tab {
    background-color:#e5e5e5;
}
QTabBar::tab::selected {
    background-color:#ffca3a;
}
"""

def clickable(widget):
    class Filter(QObject):
        clicked = pyqtSignal()

        def eventFilter(self, obj, event):
            if obj == widget:
                if event.type() == QEvent.MouseButtonRelease:
                    if obj.rect().contains(event.pos()):
                        self.clicked.emit()
                        return True

            return False

    filter = Filter(widget)
    widget.installEventFilter(filter)
    return filter.clicked


class cdrgui(QMainWindow, QWidget):

    def __init__(self):
        super(cdrgui, self).__init__()
        self.ui()

    def ui(self):
        self.cdrstep = 3
        self.filestep = 1
        self.qur_count = 0

        # ================== Menu ===================
        openAction = QAction(QIcon(':/img/open.png'), 'Open', self)
        openAction.setShortcut('Ctrl+D')
        openAction.setStatusTip('Open')
        openAction.triggered.connect(self.fileopen)

        RefreshAction = QAction(QIcon(':/img/refresh3.png'), 'Refresh', self)
        RefreshAction.setShortcut('F5')
        RefreshAction.setStatusTip('Refresh')
        RefreshAction.triggered.connect(self.Refresh)

        exitAction = QAction(QIcon(':/img/exit3.png'), 'Exit', self)
        exitAction.setShortcut('Ctrl+E')
        exitAction.setStatusTip('Exit')
        exitAction.triggered.connect(qApp.quit)

        # ============== Menu Step ==============
        stepAction = QMenu('CDR Step', self)
        stepAction.setIcon(QIcon(':/img/step2.png'))
        stepGroup = QActionGroup(stepAction)
        step = ['Step 1 : Weak', 'Step 2 : Mean', 'Step 3 : Strong']

        for check in step:
            stepCheck = QAction(check, stepAction, checkable=True, checked=check == step[0])
            stepAction.addAction(stepCheck)
            stepGroup.addAction(stepCheck)

        stepCheck.setChecked(True)
        stepGroup.setExclusive(True)
        stepGroup.triggered.connect(self.Step_Check)

        # ============== Menu Backup ==============
        backupAction = QMenu('File Backup', self)
        backupAction.setIcon(QIcon(':/img/step3.png'))
        backupGroup = QActionGroup(backupAction)
        backup = ['Backup', 'Delete']

        for check in backup:
            backupCheck = QAction(check, backupAction, checkable=True, checked=check == step[0])
            backupAction.addAction(backupCheck)
            backupGroup.addAction(backupCheck)

        backupCheck.setChecked(True)
        backupGroup.setExclusive(True)
        backupGroup.triggered.connect(self.Backup_Check)

        # ================ Menu CDR ================
        deleteAction = QAction(QIcon(':/img/cdr.png'), 'Delete CDR', self)
        deleteAction.setShortcut('F3')
        deleteAction.setStatusTip('Delete CDR')
        deleteAction.triggered.connect(self.Delete_cdr)

        # ================== help ==================
        helpAction = QAction(QIcon(':/img/help.png'), 'About' ,self)
        helpAction.setStatusTip('About')
        helpAction.triggered.connect(self.help)

        # =============== extension ================
        extensionAction = QAction(QIcon(':/img/registry.png'), 'Change' ,self)
        extensionAction.setStatusTip('Change')
        extensionAction.triggered.connect(Reg_Change)

        extensionAction2 = QAction(QIcon(':/img/registry2.png'), 'Recover', self)
        extensionAction2.setStatusTip('Recover')
        extensionAction2.triggered.connect(Reg_Recover)

        # ============== QuarantineAction ===========
        QuarantineAction = QAction(QIcon(':/img/scan.png'), 'Scan', self)
        QuarantineAction.setStatusTip('Quarantine Scan')
        QuarantineAction.triggered.connect(self.Quarantine_Scan)

        # ================== Menu ==================
        self.statusBar()
        menubar = QMenuBar(self)
        menubar.setGeometry(QRect(0, 0, 1060, 22))
        menubar.setNativeMenuBar(False)

        fileMenu = menubar.addMenu(' File ')
        menubar.setFont(QFont('Hack', 8))
        fileMenu.addAction(openAction)
        fileMenu.addAction(RefreshAction)
        fileMenu.addAction(exitAction)

        cdrMenu = menubar.addMenu(' CDR ')
        cdrMenu.addAction(deleteAction)

        optionMenu = menubar.addMenu(' Option ')
        optionMenu.addMenu(stepAction)
        optionMenu.addMenu(backupAction)

        extension = menubar.addMenu('  Extension  ')
        extension.addAction(extensionAction)
        extension.addAction(extensionAction2)

        Quarantine = menubar.addMenu('  Quarantine  ')
        Quarantine.addAction(QuarantineAction)

        helpMenu = menubar.addMenu(' Help ')
        helpMenu.addAction(helpAction)

        self.centralwidget = QWidget(self)
        self.centralwidget.setObjectName("centralwidget")

        self.tabWidget = QTabWidget(self.centralwidget)
        self.tabWidget.setObjectName("tabWidget")
        self.tabWidget.setStyleSheet('background-color: gray;')
        # self.tabWidget.currentChanged.connect(self.click)

        self.gridLayout = QGridLayout(self.centralwidget)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.gridLayout.setObjectName("gridLayout")
        self.gridLayout.addWidget(self.tabWidget, 0, 0, 1, 1)

        self.setWindowTitle(' AVE MARIA  (Anti Virus Engine)')
        self.resize(1000, 800)
        self.setWindowIcon(QIcon(':/img/title3.png'))
        self.setCentralWidget(self.centralwidget)
        self.setMenuBar(menubar)
        # self.setGeometry(600, 260, 500, 600)
        self.show()

    def tabCreate(self):
        self.tab = QWidget()

        self.widget = QWidget(self)
        self.widget.setObjectName("widget")
        self.widget.setStyleSheet('background-color: white;')

        self.fileTView = QTreeWidget(self.widget)
        self.fileTView.setObjectName("fileTView")
        self.fileTView.headerItem().setText(0, "1")
        self.fileTView.setHeaderHidden(True)
        self.fileTView.doubleClicked.connect(self.on_doubleClicked)

        self.tablewidget = QTableWidget(self.widget)
        self.tablewidget.setObjectName("tablewidget")
        self.tablewidget.setRowCount(9)
        self.tablewidget.setColumnCount(1)
        row_header = [' Virus Scan  ', '      Name', '    File size', '     ZoneID', '       MD5', '      SHA1',
                       '    Created', '    Modified', '  Accessed']
        self.tablewidget.setVerticalHeaderLabels(row_header)
        self.tablewidget.verticalHeader().resizeContentsPrecision()
        self.tablewidget.setHorizontalHeaderLabels(["Content"])
        self.tablewidget.horizontalHeader().setStretchLastSection(True)
        self.tablewidget.horizontalHeader().setVisible(False)
        self.tablewidget.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tablewidget.setFont(QFont('맑은 고딕', 9))

        # font = QFont("DejaVu Sans Mono", 8, QFont.Normal, True)
        self.hexText = QTextEdit(self)
        self.hexText.setObjectName("hexText")
        self.hexText.setReadOnly(True)
        self.hexText.setCurrentFont(QFont('Consolas', 10))
        self.hexText.setStyleSheet('background-color: white;')

        self.textedit = QTextEdit(self)
        self.textedit.setObjectName("textedit")
        self.textedit.setReadOnly(True)
        self.textedit.setStyleSheet('background-color: white;')

        self.plot_spli2 = QSplitter(Qt.Vertical)
        self.plot_spli2.addWidget(self.hexText)
        self.plot_spli2.addWidget(self.textedit)
        self.plot_spli2.setStretchFactor(0, 4)
        self.plot_spli2.setStretchFactor(1, 3)
        self.plot_spli2.setStyleSheet('background-color: white;')

        self.plot_spli = QSplitter(Qt.Horizontal)
        self.plot_spli.addWidget(self.widget)
        self.plot_spli.addWidget(self.plot_spli2)
        self.plot_spli.setStretchFactor(0, 1)
        self.plot_spli.setStretchFactor(1, 2)
        self.plot_spli.setStyleSheet('background-color: white;')

        self.horizontalLayout = QHBoxLayout(self.tab)
        self.horizontalLayout.setSizeConstraint(QLayout.SetDefaultConstraint)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.horizontalLayout.addWidget(self.plot_spli)

        self.verticalLayout = QVBoxLayout(self.widget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setSpacing(0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.verticalLayout.addWidget(self.fileTView)
        self.verticalLayout.addWidget(self.tablewidget)
        self.verticalLayout.setStretch(0, 1)

        return self.tab

    def Quarantine_Scan(self):
        self.fopen = QFileDialog.getOpenFileName(self, '파일열기', directory='C:\CDR\Quarantine',
                                                 filter='암호화 파일(*.qua)')
        f = open(self.fopen[0], 'rb')
        data = f.read()


        a = self.tabWidget.currentIndex()
        index = self.tabWidget.addTab(self.tabCreate(), QFileInfo(self.fopen[0]).fileName())
        self.tabWidget.setCurrentIndex(index)
        self.tabWidget.setTabsClosable(True)
        self.tabWidget.tabCloseRequested.connect(self.closeTab)
        self.tabWidget.setTabIcon(a + 1, QIcon(':/img/hwp2.png'))

        a = self.tabWidget.currentIndex()
        if a == 1:
            self.tabWidget.removeTab(0)

        # ==================== File Data =====================
        filesize = os.path.getsize(self.fopen[0])
        ctime = time.strftime('%Y-%m-%d', time.localtime(os.path.getctime(self.fopen[0])))
        mtime = time.strftime('%Y-%m-%d', time.localtime(os.path.getmtime(self.fopen[0])))
        atime = time.strftime('%Y-%m-%d', time.localtime(os.path.getatime(self.fopen[0])))

        # ================== ADD Table Item ==================
        self.Virus_Scan()  # Scan
        self.tablewidget.setItem(0, 1, QTableWidgetItem(QFileInfo(self.fopen[0]).fileName()))  # Name
        if filesize <= 1000000:
            self.tablewidget.setItem(0, 2, QTableWidgetItem("%.2f KB" % (filesize / 1024)))  # File Size
        else:
            self.tablewidget.setItem(0, 2, QTableWidgetItem("%.2f MB" % (filesize / (1024.0 * 1024.0))))  # File Size
        self.tablewidget.setItem(0, 3, QTableWidgetItem(self.Zone_Check(self.fopen[0])))  # Zone ID
        self.tablewidget.setItem(0, 4, QTableWidgetItem(hashlib.md5(data).hexdigest()))  # MD5
        self.tablewidget.setItem(0, 5, QTableWidgetItem(hashlib.sha1(data).hexdigest()))  # SHA1
        self.tablewidget.setItem(0, 6, QTableWidgetItem(str(ctime)))  # Created
        self.tablewidget.setItem(0, 7, QTableWidgetItem(str(mtime)))  # Modified
        self.tablewidget.setItem(0, 8, QTableWidgetItem(str(atime)))  # Accessed
        # ====================================================

        self.fileTView.clear()
        ole = oleparser.OleFileIO(self.fopen[0])
        pro = oleparser.OleFileIO.listdir2(ole)
        preStorage = ""
        default_stream = [['DocInfo'], ['FileHeader'], ['\x05HwpSummaryInformation'], ['PrvImage'], ['PrvText']]

        filename = QTreeWidgetItem(self.fileTView)
        filename.setText(0, QFileInfo(self.fopen[0]).fileName())
        filename.setIcon(0, QIcon(':/img/hwp2.png'))

        for i in pro:
            if (i[0] != preStorage):
                root = QTreeWidgetItem(filename)
                root.setIcon(0, QIcon(':/img/folder.png'))
                root.setText(0, i[0])
                if i in default_stream:
                    root.setIcon(0, QIcon(':/img/file.png'))
                    root.setText(0, i[0])
            preStorage = i[0]
            for j in i[1:]:
                nextValue = QTreeWidgetItem(root)
                nextValue.setIcon(0, QIcon(':/img/file.png'))
                nextValue.setText(0, j)

        # ================== PrvText View ==================
        encode = ole.openstream('PrvText').read()
        decode = encode.decode('UTF-16')
        self.textedit.append(str(decode))
        # ==================================================

        ole.close()
        f.close()

    def help(self):
        QMessageBox.about(self, 'About', '이 프로그램은 상업적인 \n용도로 쓰이지 않습니다.'
                                         '\n\n프로그램을 이용한 후 \n책임은 본인에게 있습니다.')

    def Refresh(self):
        f = open(self.fopen[0], 'rb')
        data = f.read()

        index = self.tabWidget.addTab(self.tabCreate(), QFileInfo(self.fopen[0]).fileName())
        self.tabWidget.setCurrentIndex(index)
        self.tabWidget.setTabsClosable(True)
        self.tabWidget.tabCloseRequested.connect(self.closeTab)

        a = self.tabWidget.currentIndex()
        if a == 1:
            self.tabWidget.removeTab(0)

        # ==================== File Data =====================
        filesize = os.path.getsize(self.fopen[0])
        ctime = time.strftime('%Y-%m-%d', time.localtime(os.path.getctime(self.fopen[0])))
        mtime = time.strftime('%Y-%m-%d', time.localtime(os.path.getmtime(self.fopen[0])))
        atime = time.strftime('%Y-%m-%d', time.localtime(os.path.getatime(self.fopen[0])))

        # ================== ADD Table Item ==================
        self.Virus_Scan()  # Scan
        self.tablewidget.setItem(0, 1, QTableWidgetItem(QFileInfo(self.fopen[0]).fileName()))  # Name
        if filesize <= 1000000:
            self.tablewidget.setItem(0, 2, QTableWidgetItem("%.2f KB" % (filesize / 1024)))  # File Size
        else:
            self.tablewidget.setItem(0, 2, QTableWidgetItem("%.2f MB" % (filesize / (1024.0 * 1024.0))))  # File Size
        self.tablewidget.setItem(0, 3, QTableWidgetItem(self.Zone_Check(self.fopen[0])))  # Zone ID
        self.tablewidget.setItem(0, 4, QTableWidgetItem(hashlib.md5(data).hexdigest()))  # MD5
        self.tablewidget.setItem(0, 5, QTableWidgetItem(hashlib.sha1(data).hexdigest()))  # SHA1
        self.tablewidget.setItem(0, 6, QTableWidgetItem(str(ctime)))  # Created
        self.tablewidget.setItem(0, 7, QTableWidgetItem(str(mtime)))  # Modified
        self.tablewidget.setItem(0, 8, QTableWidgetItem(str(atime)))  # Accessed
        # ====================================================
        self.fileTView.clear()
        ole = oleparser.OleFileIO(self.fopen[0])
        pro = oleparser.OleFileIO.listdir2(ole)
        preStorage = ""
        default_stream = [['DocInfo'], ['FileHeader'], ['\x05HwpSummaryInformation'], ['PrvImage'], ['PrvText']]

        # ================== PrvText View ==================
        encode = ole.openstream('PrvText').read()
        decode = encode.decode('UTF-16')
        self.textedit.append(str(decode))
        # ==================================================

        filename = QTreeWidgetItem(self.fileTView)
        filename.setText(0, QFileInfo(self.fopen[0]).fileName())

        for i in pro:
            if (i[0] != preStorage):
                root = QTreeWidgetItem(filename)
                root.setIcon(0, QIcon(':/img/folder.png'))
                root.setText(0, i[0])
                if i in default_stream:
                    root.setIcon(0, QIcon(':/img/file.png'))
                    root.setText(0, i[0])
            preStorage = i[0]
            for j in i[1:]:
                nextValue = QTreeWidgetItem(root)
                nextValue.setIcon(0, QIcon(':/img/file.png'))
                nextValue.setText(0, j)

        ole.close()
        f.close()

    # def click(self):
        # self.a = self.tabWidget.currentIndex()
        # self.b = self.tabWidget.tabText(self.a)

    @pyqtSlot("QModelIndex")
    def on_doubleClicked(self, ix):
        self.hexText.clear()

        storage = ['BinData', 'BodyText', 'DocHistory', 'DocOptions', 'Scripts', 'ViewText', 'XML Template']
        ole = oleparser.OleFileIO(self.fopen[0])
        h = ole.listdir2()
        gp = QCursor.pos()
        lp = self.fileTView.viewport().mapFromGlobal(gp)
        ix_ = self.fileTView.indexAt(lp)
        ix_data = str(ix_.data())

        if ix_data in storage:
            pass
        elif ix_data not in storage:
            for i in h:
                if ix_data in i:
                    x = ole.openstream(i)
                    c = x.read()
                    # self.hexText.append(self.hexdump(c))
                    self.dumpgen(c)
        ole.close()
        return ix.data

    def dumpgen(self, data):
        """
        Generator that produces strings:
        '00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................'
        """
        generator = hexdump.genchunks(data, 16)
        for addr, d in enumerate(generator):
            # 00000000:
            color = QColor(238,108,77)
            self.hexText.setTextColor(color)
            offset = '%08X: ' % (addr * 16)
            self.hexText.append(offset)

            # 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
            color = QColor(0, 0, 0)
            self.hexText.setTextColor(color)
            dumpstr = hexdump.dump(d)
            hext = dumpstr[:8 * 3]
            if len(d) > 8:  # insert separator if needed
                hext += ' ' + dumpstr[8 * 3:]
            # ................
            # calculate indentation, which may be different for the last line
            pad = 2
            if len(d) < 16:
                pad += 3 * (16 - len(d))
            if len(d) <= 8:
                pad += 1
            hext += ' ' * pad
            self.hexText.insertPlainText(hext)

            color = QColor(3, 64, 120)
            self.hexText.setTextColor(color)
            str = ''
            for byte in d:
                if not hexdump.PY3K:
                    byte = ord(byte)
                if 0x20 <= byte <= 0x7E:
                    str += chr(byte)
                else:
                    str += '.'
            self.hexText.insertPlainText(str)

    #이거 안 썼어요!
    def hexdump(self, data, result='print'):
        if hexdump.PY3K and type(data) == str:
            raise TypeError('Abstract unicode data')

        gen = hexdump.dumpgen(data)
        if result == 'generator':
            return gen
        elif result == 'return':
            return '\n'.join(gen)
        elif result == 'print':
            for line in gen:
                self.hexText.append(str(line))
        else:
            raise ValueError('Unknown value of result argument')

    def fileopen(self):
        self.fopen = QFileDialog.getOpenFileName(self, '파일열기', filter='한글(*.hwp)')
        f = open(self.fopen[0], 'rb')
        data = f.read()
        # ============== 검역소 =============
        os.system("mkdir c:\CDR\Quarantine")

        check_name = os.path.basename(self.fopen[0]).replace('.hwp', '.qua')
        self.qur_count += 1

        qur_loc = 'C:/CDR/Quarantine/' + str(self.qur_count) + '-' + check_name
        qur_w = open(qur_loc, 'wb')
        qur_w.write(data)

        a = self.tabWidget.currentIndex()
        index = self.tabWidget.addTab(self.tabCreate(),QFileInfo(self.fopen[0]).fileName())
        self.tabWidget.setCurrentIndex(index)
        self.tabWidget.setTabsClosable(True)
        self.tabWidget.tabCloseRequested.connect(self.closeTab)
        self.tabWidget.setTabIcon(a+1, QIcon(':/img/hwp2.png'))

        a = self.tabWidget.currentIndex()
        if a == 1:
            self.tabWidget.removeTab(0)

        # ==================== File Data =====================
        filesize = os.path.getsize(self.fopen[0])
        ctime = time.strftime('%Y-%m-%d', time.localtime(os.path.getctime(self.fopen[0])))
        mtime = time.strftime('%Y-%m-%d', time.localtime(os.path.getmtime(self.fopen[0])))
        atime = time.strftime('%Y-%m-%d', time.localtime(os.path.getatime(self.fopen[0])))

        # ================== ADD Table Item ==================
        self.Virus_Scan()  # Scan
        self.tablewidget.setItem(0, 1, QTableWidgetItem(QFileInfo(self.fopen[0]).fileName()))  # Name
        if filesize <= 1000000:
            self.tablewidget.setItem(0, 2, QTableWidgetItem("%.2f KB" % (filesize / 1024)))  # File Size
        else:
            self.tablewidget.setItem(0, 2, QTableWidgetItem("%.2f MB" % (filesize / (1024.0 * 1024.0))))  # File Size
        self.tablewidget.setItem(0, 3, QTableWidgetItem(self.Zone_Check(self.fopen[0])))  # Zone ID
        self.tablewidget.setItem(0, 4, QTableWidgetItem(hashlib.md5(data).hexdigest()))  # MD5
        self.tablewidget.setItem(0, 5, QTableWidgetItem(hashlib.sha1(data).hexdigest()))  # SHA1
        self.tablewidget.setItem(0, 6, QTableWidgetItem(str(ctime)))  # Created
        self.tablewidget.setItem(0, 7, QTableWidgetItem(str(mtime)))  # Modified
        self.tablewidget.setItem(0, 8, QTableWidgetItem(str(atime)))  # Accessed
        # ====================================================


        self.fileTView.clear()
        ole = oleparser.OleFileIO(self.fopen[0])
        pro = oleparser.OleFileIO.listdir2(ole)
        preStorage = ""
        default_stream = [['DocInfo'], ['FileHeader'], ['\x05HwpSummaryInformation'], ['PrvImage'], ['PrvText']]

        filename = QTreeWidgetItem(self.fileTView)
        filename.setText(0, QFileInfo(self.fopen[0]).fileName())
        filename.setIcon(0, QIcon(':/img/hwp2.png'))

        for i in pro:
            if (i[0] != preStorage):
                root = QTreeWidgetItem(filename)
                root.setIcon(0, QIcon(':/img/folder.png'))
                root.setText(0, i[0])
                if i in default_stream:
                    root.setIcon(0, QIcon(':/img/file.png'))
                    root.setText(0, i[0])
            preStorage = i[0]
            for j in i[1:]:
                nextValue = QTreeWidgetItem(root)
                nextValue.setIcon(0, QIcon(':/img/file.png'))
                nextValue.setText(0, j)

        # ================== PrvText View ==================
        encode = ole.openstream('PrvText').read()
        decode = encode.decode('UTF-16')
        self.textedit.append(str(decode))
        # ==================================================

        ole.close()
        f.close()

    def closeTab(self, index):
        tab = self.tabWidget.widget(index)
        tab.deleteLater()
        self.tabWidget.removeTab(index)

    def Step_Check(self, stepCheck):
        if stepCheck.text() == 'Step 1 : Weak':
            self.cdrstep = 1
        if stepCheck.text() == 'Step 2 : Mean':
            self.cdrstep = 2
        if stepCheck.text() == 'Step 3 : Strong':
            self.cdrstep = 3

    def Backup_Check(self, backupCheck):
        if backupCheck.text() == 'Delete':
            self.filestep = 1
        if backupCheck.text() == 'Backup':
            self.filestep = 2

    def Delete_cdr(self):
        self.delete_file = OFC(self.fopen[0], write_mode=True)

        if os.path.isfile(self.fopen[0]):
            if self.filestep == 2:
                f = open(self.fopen[0], 'rb')
                data = f.read()
                a = (self.fopen[0] + '.backup')
                wr = open(a, 'wb')
                wr.write(data)

            self.delete_file.deleteall(str(self.cdrstep))
            QMessageBox.about(self, 'AVE MARIA', 'Delete CDR Success')
        else:
            QMessageBox.about(self, 'AVE MARIA', 'Error')
        self.delete_file.close()

    def Virus_Scan(self):
        api_key = '987fb7cb2684fd18d4ad6579cafcde0154f76d4a6ac8fabe69fed553447687db'
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        url2 = 'https://www.virustotal.com/vtapi/v2/file/scan'


        f = open(self.fopen[0], 'rb')
        data = f.read()
        resource = hashlib.md5(data).hexdigest()
        params = {'apikey': api_key, 'resource': resource}
        dic = requests.get(url, params=params).json()

        if dic['response_code'] == 1:
            for a in dic['scans'].keys():
                for b in dic['scans'][a].keys():
                    if b == 'detected':
                        if dic['scans'][a]['detected'] == False:
                            pass
                            # print('Anti Engine : ', a, 'Clean')

                        elif dic['scans'][a]['detected'] == True:
                            pass
                            # print('Anti Engine : ', a, 'Vrius')

            if dic['positives'] == 0:
                # print('Scan Total : ' + str(dic['total']))
                # print('Virus Count : ' + str(dic['positives']))
                item1 = QTableWidgetItem('Clean')
                item1.setBackground(Qt.darkGreen)
                item1.setForeground(Qt.white)
                self.tablewidget.setItem(0, 0, item1)
            else:
                # print(str(dic['total']))
                # print(str(dic['positives']))
                item2 = QTableWidgetItem('Virus')
                item2.setBackground(Qt.darkRed)
                item2.setForeground(Qt.white)
                self.tablewidget.setItem(0, 0, item2)
        else:
            # print('This is Unknown file')
            item3 = QTableWidgetItem('Unknown')
            item3.setBackground(Qt.black)
            item3.setForeground(Qt.white)
            self.tablewidget.setItem(0, 0, item3)
            self.Zone_Check(self.fopen[0])

    # ================= Zone ID =================
    def Zone_Check(self, file):
        # print(file)
        cmd = 'more < "'
        cmd += str(file)
        cmd += ':Zone.Identifier"'
        sysMsg = subprocess.getstatusoutput(cmd)
        for split in sysMsg:
            pass

        x = split.split()
        Zone_Check = False

        if x[1] == 'ZoneId=4':
            Zone_Check = True
            self.zone_id = '4'
        if x[1] == 'ZoneId=3':
            Zone_Check = True
            self.zone_id = '3'
        if x[1] == 'ZoneId=2':
            self.zone_id = '2'
        if x[1] == 'ZoneId=1':
            self.zone_id = '1'
        else:
            if not Zone_Check:
                self.zone_id = '0'

        return self.zone_id

# ===================================== Error ========================================
class Error(Exception):
    pass

# ==================================== Git Hub =======================================
class HexDump:
    def File(self, File_Name, start, size=0x200, width=16):
        f = open(File_Name, "rb")
        f.seek(start)
        row = start % width
        col = (start / width) * width
        root_size = 0
        line_start = row
        while True:
            if (root_size + (width - line_start) < size):
                r_char = (width - line_start)
                root_size += (width - line_start)
            else:
                r_char = size - root_size
                root_size = size
            line = f.read(r_char)
            if len(line) == 0:
                break
            output = "%08X : " % col
            output += line_start * "   " \
                      + "".join("%02x " % ord(c) for c in line)
            output += "  " \
                      + (width - (line_start + r_char)) * "   "
            output += line_start * " "
            output += "".join(['.', c][self.IsPrint(c)] for c in line)
            col += width
            line_start = 0
            if root_size == size:
                break
        f.close()

    def Buffer(self, buf, start, size=0x200, width=16):
        if len(buf) < size:
            size = len(buf)
        row = start % width
        col = int(start / width)
        root_size = 0
        line_start = row + (col * width)
        while True:
            line = buf[line_start:width * (col + 1)]
            if len(line) == 0:
                break
            if ((root_size + len(line)) < size):
                pass
            else:
                line = line[0:(size - root_size)]
                root_size = size - len(line)
            out_val = int((line_start / width) * width)
            output = "%08X : " % (out_val)
            output += row * "   " \
                      + "".join("%02x " % ord(chr(c)) for c in line)
            output += "  " \
                      + (width - (row + len(line))) * "   "
            output += row * " "
            output += "".join(['.', chr(c)][self.IsPrint(c)] for c in line)
            line_start = width * (col + 1)
            col += 1
            row = 0
            root_size += len(line)
            if root_size == size:
                break

    def IsPrint(self, char):
        c = ord(chr(char))
        if c >= 0x20 and c < 0x80:
            return True
        else:
            return False

def c_uint16(buf, off, be=False):
    endian = '<'
    if be:
        endian = '>'

    return struct.unpack(endian + 'H', buf[off:off + 2])[0]


def c_uint32(buf, off, be=False):
    endian = '<'
    if be:
        endian = '>'

    return struct.unpack(endian + 'L', buf[off:off + 4])[0]


def c_uint64(buf, off, be=False):
    endian = '<'
    if be:
        endian = '>'

    return struct.unpack(endian + 'Q', buf[off:off + 8])[0]


def Base64Encode(x):
    ct = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._'
    if x > 63:
        return None

    return ord(ct[x])


def Decoder(name):
    wch = []
    och = []
    for i in range(int(len(name) / 2)):
        wch.append(c_uint16(name, i * 2))
    for ch in wch:
        if 0x3800 <= ch <= 0x4840:
            if ch >= 0x4800:
                ch = Base64Encode(ch - 0x4800)
                if not ch:
                    continue
            else:
                ch -= 0x3800
                och.append(Base64Encode(ch & 0x3f))
                ch = Base64Encode(((ch >> 6) & 0x3f))

        och.append(ch)

    ret_str = b''

    for ch in och:
        ret_str += struct.pack('<H', ch)

    return ret_str
# ====================================================================================


# ================================ Parser & Reader ===================================
def Sector_Chain(tn, BBAT_or_SBAT_fat):
    ret = []

    fat = BBAT_or_SBAT_fat

    next_b = tn

    if next_b != 0xfffffffe:
        ret.append(next_b)

        while True:
            try:
                next_b = fat[next_b]
                if next_b == 0xfffffffe:
                    break

                if len(ret) % 10000 == 0:
                    if next_b in ret:
                        break

                ret.append(next_b)
            except KeyError:
                break

    return ret


def Reader_ID(buf, tn, BBAT_Size):
    off = (tn + 1) * BBAT_Size
    return buf[off:off + BBAT_Size]


def Sector_Chain_Array(buf):
    Chain_Array = buf[0x4c:0x200]
    BBAT_Count = c_uint32(buf, 0x2c)

    Extra_Strat = c_uint32(buf, 0x44)
    Extra_Count = c_uint32(buf, 0x48)

    BBAT_Size = 1 << c_uint16(buf, 0x1e)

    if BBAT_Count > 109:
        next_b = Extra_Strat

        for i in range(Extra_Count):
            tmp_data = Reader_ID(buf, next_b, BBAT_Size)
            Chain_Array += tmp_data[:-4]
            next_b = c_uint32(tmp_data, BBAT_Size - 4)

    return Chain_Array[:BBAT_Count * 4], BBAT_Count, Extra_Count, Extra_Strat


def Sector_Chain_Array_Off(buf, idx):
    BBAT_Count = c_uint32(buf, 0x2c)
    Extra_Strat = c_uint32(buf, 0x44)
    BBAT_Size = 1 << c_uint16(buf, 0x1e)
    if idx >= BBAT_Count:
        return -1
    if idx <= 109:
        return 0x4c + (idx * 4)
    else:
        t_idx = idx - 109
        seg = (t_idx / ((BBAT_Size / 4) - 1)) + (1 if (t_idx % ((BBAT_Size / 4) - 1)) else 0)
        off = (t_idx % ((BBAT_Size / 4) - 1))
        next_b = Extra_Strat
        for i in range(seg):
            if next_b == 0xfffffffe:
                return -1
            t_buf = Reader_ID(buf, next_b, BBAT_Size)
            next_b = c_uint32(t_buf, BBAT_Size - 4)
        return (next_b + 1) * BBAT_Size + (off * 4)


def Check_OFC(filename):
    try:
        buf = open(filename, 'rb').read(8)

        if buf == 'D0CF11E0A1B11AE1'.decode('hex'):
            return True
    except IOError:
        pass

    return False
# ====================================================================================



# ==================================== Parser ========================================
class OFC:
    def __init__(self, File, write_mode=False):
        self.Check = False
        if isinstance(File, str):
            if os.path.exists(File):
                self.Check = True
                self.File_Name = File
                self.f = open(File, 'rb')
                read = self.f.read()
            else:
                read = File
        else:
            raise Error('Input data is invalid.')

        self.write_mode = write_mode

        self.Signature = None
        self.BBAT_Size = None
        self.SBAT_Size = None
        self.Chain_Array = None
        self.BBAT = None
        self.BBAT_Array = {}
        self.SBAT = None
        self.Root = None
        self.Ofc_Array = None
        self.SBAT_Sector = None
        self.Root_Chain = None
        self.Exploit = []
        self.Deep = None
        self.ALL_Array = None

        self.init(read)

    def init(self, buf):
        self.Signature = buf
        self.BBAT_Size = 0
        self.SBAT_Size = 0

        self.Deep = 0
        self.ALL_Array = []

        self.parse()

    def close(self):
        if self.Check:
            self.f.close()

            if self.write_mode:
                open(self.File_Name, 'wb').write(self.Signature)

    def parse(self):
        buf = self.Signature[:8]
        if buf != codecs.decode('D0CF11E0A1B11AE1', 'hex'):
            raise Error('Not Ofc Signature')
        self.BBAT_Size = 1 << c_uint16(self.Signature, 0x1e)
        self.SBAT_Size = 1 << c_uint16(self.Signature, 0x20)
        if self.BBAT_Size % 0x200 != 0 or self.SBAT_Size != 0x40:
            return False
        self.Chain_Array, BBAT_Count, Extra_Count, Extra_Strat = \
            Sector_Chain_Array(self.Signature)
        if len(self.Chain_Array) / 4 < BBAT_Count:
            return False
        self.BBAT = b''
        for i in range(BBAT_Count):
            tn = c_uint32(self.Chain_Array, i * 4)
            self.BBAT += Reader_ID(self.Signature, tn, self.BBAT_Size)
        self.BBAT_Array = {}
        for i in range(int(len(self.BBAT) / 4)):
            n = c_uint32(self.BBAT, i * 4)
            self.BBAT_Array[i] = n
        Root_startblock = c_uint32(self.Signature, 0x30)
        Root_Chain = Sector_Chain(Root_startblock, self.BBAT_Array)
        self.Root_Chain = Root_Chain
        self.Root = b''
        for tn in Root_Chain:
            self.Root += Reader_ID(self.Signature, tn, self.BBAT_Size)
        SBAT_Start_Sector = c_uint32(self.Signature, 0x3c)
        count_of_SBAT_blocks = c_uint32(self.Signature, 0x40)
        SBAT_Chain = Sector_Chain(SBAT_Start_Sector, self.BBAT_Array)
        self.SBAT = b''
        for tn in SBAT_Chain:
            self.SBAT += Reader_ID(self.Signature, tn, self.BBAT_Size)
        self.SBAT_fat = {}
        for i in range(int(len(self.SBAT) / 4)):
            n = c_uint32(self.SBAT, i * 4)
            self.SBAT_fat[i] = n
        self.Ofc_Array = []
        for i in range(int(len(self.Root) / 0x80)):
            data = {}
            Ofc_Array = self.Root[i * 0x80:(i + 1) * 0x80]
            tmp_size = min(c_uint16(Ofc_Array, 0x40), 0x40)
            if tmp_size != 0:
                if ord(chr(Ofc_Array[0])) & 0xF0 == 0x00 and ord(chr(Ofc_Array[1])) == 0x00:
                    name = b'_\x00' + Ofc_Array[2:tmp_size - 2]
                else:
                    name = Ofc_Array[0:tmp_size - 2]
                data['Name'] = Decoder(name).decode('UTF-16LE', 'replace')
            else:
                data['Name'] = ''
            data['Type'] = ord(chr(Ofc_Array[0x42]))
            data['Left'] = c_uint32(Ofc_Array, 0x44)
            data['Right'] = c_uint32(Ofc_Array, 0x48)
            data['Child'] = c_uint32(Ofc_Array, 0x4c)
            data['Start'] = c_uint32(Ofc_Array, 0x74)
            data['Size'] = c_uint32(Ofc_Array, 0x78)
            data['Valid'] = False
            cve_clsids = ['\x4B\xF0\xD1\xBD\x8B\x85\xD1\x11\xB1\x6A\x00\xC0\xF0\x28\x36\x28',
                          '\xE0\xF5\x6B\x99\x44\x80\x50\x46\xAD\xEB\x0B\x01\x39\x14\xE9\x9C',
                          '\xE6\x3F\x83\x66\x83\x85\xD1\x11\xB1\x6A\x00\xC0\xF0\x28\x36\x28',
                          '\x5F\xDC\x81\x91\x7D\xE0\x8A\x41\xAC\xA6\x8E\xEA\x1E\xCB\x8E\x9E',
                          '\xB6\x90\x41\xC7\x89\x85\xD1\x11\xB1\x6A\x00\xC0\xF0\x28\x36\x28'
                          ]
            if Ofc_Array[0x50:0x60] in cve_clsids:
                self.Exploit.append('Exploit.OLE.CVE-2012-0158')
                return False
            self.Ofc_Array.append(data)
        if self.Check_Ofc_Valid() is False:
            return False

        self.Deep = 0
        self.ALL_Array = []
        try:
            self.Ofc_Path()
        except IndexError:
            pass
        self.SBAT_Sector = Sector_Chain(self.Ofc_Array[0]['Start'], self.BBAT_Array)
        return True

    def Check_Ofc_Valid(self):
        Scan_Ofc = [0]
        f = []
        if len(self.Ofc_Array) == 0:
            return False
        if self.Ofc_Array[0]['Child'] != 0xffffffff and self.Ofc_Array[0]['Type'] == 5:
            f.append(self.Ofc_Array[0]['Child'])
            Scan_Ofc.append(self.Ofc_Array[0]['Child'])
            self.Ofc_Array[0]['Valid'] = True
        if len(f) == 0:
            return False
        while len(f):
            x = f.pop(0)
            try:
                if self.Ofc_Array[x]['Type'] != 1 and self.Ofc_Array[x]['Type'] != 2 and len(self.Ofc_Array[x]['Name']) == 0:
                    continue
            except IndexError:
                if (x & 0x90900000) == 0x90900000:
                    self.Exploit.append('Exploit.OLE.CVE-2003-0820')
                    return False
                else:
                    self.Exploit.append('Exploit.OLE.CVE-2003-0347')
                    return False
            self.Ofc_Array[x]['Valid'] = True
            if self.Ofc_Array[x]['Left'] != 0xffffffff:
                if self.Ofc_Array[x]['Left'] in Scan_Ofc:
                    self.Ofc_Array[x]['Left'] = 0xffffffff
                else:
                    f.append(self.Ofc_Array[x]['Left'])
                    Scan_Ofc.append(self.Ofc_Array[x]['Left'])
            if self.Ofc_Array[x]['Right'] != 0xffffffff:
                if self.Ofc_Array[x]['Right'] in Scan_Ofc:
                    self.Ofc_Array[x]['Right'] = 0xffffffff
                else:
                    f.append(self.Ofc_Array[x]['Right'])
                    Scan_Ofc.append(self.Ofc_Array[x]['Right'])
            if self.Ofc_Array[x]['Child'] != 0xffffffff:
                if self.Ofc_Array[x]['Child'] in Scan_Ofc:
                    self.Ofc_Array[x]['Child'] = 0xffffffff
                else:
                    f.append(self.Ofc_Array[x]['Child'])
                    Scan_Ofc.append(self.Ofc_Array[x]['Child'])
        return True

    def Ofc_Path(self, node=0, fix=b''):
        if node == 0:
            Ofc_Array_name = b''
            name = fix + Ofc_Array_name
        else:
            if self.Ofc_Array[node]['Valid'] is False:
                return 0
            Ofc_Array_name = self.Ofc_Array[node]['Name'].encode('cp949', 'ignore')
            name = fix + b'/' + Ofc_Array_name
            data = {'Node': node, 'Name': name[1:], 'Type': self.Ofc_Array[node]['Type']}
            self.ALL_Array.append(data)
        if self.Ofc_Array[node]['Child'] != 0xFFFFFFFF:
            self.Deep += 1
            self.Ofc_Path(self.Ofc_Array[node]['Child'], name)
            self.Deep -= 1
        if self.Ofc_Array[node]['Left'] != 0xFFFFFFFF:
            self.Ofc_Path(self.Ofc_Array[node]['Left'], fix)
        if self.Ofc_Array[node]['Right'] != 0xFFFFFFFF:
            self.Ofc_Path(self.Ofc_Array[node]['Right'], fix)
        return 0

    def listdir(self, streams=True, storages=False):
        ret = []
        for data in self.ALL_Array:
            if data['Type'] == 2 and streams:
                ret.append(data['Name'])
            elif data['Type'] == 1 and storages:
                ret.append(data['Name'])
            else:
                pass
        return ret

    def listole(self):
        a = list()
        for data in self.ALL_Array:
            if data['Name'] != b'DocInfo':
                if data['Name'] != b'FileHeader':
                    if data['Name'] != b'_HwpSuSignaturearyInformation':
                        if data['Name'] != b'PrvImage':
                            if data['Name'] != b'PrvText':
                                a.append(data['Name'])
            else:
                pass
        return a

    def exists(self, name):
        for data in self.ALL_Array:
            if data['Name'] == name:
                return True
        else:
            return False

    def Open_Stream(self, name):
        class Stream:
            def __init__(self, parent, node):
                self.parent = parent
                self.node = node
                self.read_size = 0
                self.fat = None

            def Get_Value(self, chain):
                start = None
                end = None
                if not start:
                    start = chain.pop(0)
                e = start
                loop = False
                for x in chain:
                    if e + 1 == x:
                        e = x
                        loop = True
                        continue
                    else:
                        while loop:
                            if e == chain.pop(0):
                                break
                        end = e
                        break
                else:
                    for i in range(len(chain)):
                        chain.pop(0)
                    end = e
                return start, end

            def read(self):
                Ofc_Array = self.parent.Ofc_Array[self.node]
                sb = Ofc_Array['Start']
                size = Ofc_Array['Size']
                if size >= 0x1000:
                    self.read_size = self.parent.BBAT_Size
                    self.fat = self.parent.BBAT_Array
                else:
                    self.read_size = self.parent.SBAT_Size
                    self.fat = self.parent.SBAT_fat
                list_array = Sector_Chain(sb, self.fat)
                data = ''
                if size >= 0x1000:
                    t_list = list(list_array)
                    while len(t_list):
                        s, e = self.Get_Value(t_list)
                        off = (s + 1) * self.read_size
                        data += self.parent.Signature[off:off + self.read_size * (e - s + 1)]
                else:
                    for n in list_array:
                        div_n = self.parent.BBAT_Size / self.parent.SBAT_Size
                        off = (self.parent.SBAT_Sector[n / div_n] + 1) * self.parent.BBAT_Size
                        off += (n % div_n) * self.parent.SBAT_Size
                        data += self.parent.Signature[off:off + self.read_size]
                return data[:size]

            def close(self):
                pass

        for data in self.ALL_Array:
            if data['Name'] == name:
                tn = data['Node']
                break
        else:
            tn = -1
        if tn == -1:
            raise Error('PPS name is invalid.')
        return Stream(self, tn)

    def Write_Stream(self, name, data):
        for data in self.ALL_Array:
            if data['Name'] == name:
                tn = data['Node']
                break
        else:
            tn = -1
        if tn == -1:
            raise Error('OFC is invalid.')
        ow = Ofcwrite(self.Signature, self.Ofc_Array, self.BBAT_Size, self.SBAT_Size,
                            self.BBAT, self.BBAT_Array,
                            self.SBAT, self.SBAT_fat,
                            self.Root_Chain, self.SBAT_Sector)
        tmp = ow.write(tn, data)
        if tmp:
            self.init(tmp)

    def delete(self, name):
        for data in self.ALL_Array:
            if data['Name'] == name:
                tn = data['Node']
                break
        else:
            tn = -1
        if tn == -1:
            raise Error('PPS name is invalid.')
        ow = Ofcwrite(self.Signature, self.Ofc_Array, self.BBAT_Size, self.SBAT_Size,
                            self.BBAT, self.BBAT_Array,
                            self.SBAT, self.SBAT_fat,
                            self.Root_Chain, self.SBAT_Sector)

        Ofc_Array = self.Ofc_Array[tn]
        if Ofc_Array['Valid'] and Ofc_Array['Type'] == 2:
            tmp = ow.delete(tn)
            if tmp:
                self.init(tmp)
        elif Ofc_Array['Valid'] and Ofc_Array['Type'] == 1:
            tmp = ow.delete(tn)
            if tmp:
                self.init(tmp)

    def deleteall(self, countber):
        if countber == '3':
            body = b'BodyText'
            xml = b'XML Template'
            doc = b'DocHistory'
            viw = b'ViewText'
            for data in self.ALL_Array:
                if data['Name'] not in b'FileHeader' b'DocInfo' b'_HwpSuSignaturearyInformation' b'DocHistory' b'XML Template':
                    if data['Name'] not in b'Scripts' b'BinData' b'PrvImage' b'PrvText' b'DocOptions':
                        if body not in data['Name']:
                            if viw not in data['Name']:
                                OFC.delete(self, data['Name'])
            else:
                pass

        if countber == '2':
            jpg = b'jpg'
            bmp = b'bmp'
            rle = b'rle'
            dib = b'dib'
            gif = b'gif'
            png = b'png'
            tif = b'tif'
            tiff = b'tiff'
            raw = b'raw'
            jpeg = b'jpeg'
            img = b'img'
            body = b'BodyText'
            xml = b'XML Template'
            doc = b'DocHistory'
            viw = b'ViewText'
            for data in self.ALL_Array:
                if data['Name'] not in b'DocInfo' b'FileHeader' b'_HwpSuSignaturearyInformation' b'PrvImage':
                    if data['Name'] not in b'PrvText' b'DocOptions' b'Scripts' b'BinData' b'DocHistory' b'XML Template':
                        if body not in data['Name']:
                            if jpg not in data['Name']:
                                if bmp not in data['Name']:
                                    if rle not in data['Name']:
                                        if dib not in data['Name']:
                                            if gif not in data['Name']:
                                                if png not in data['Name']:
                                                    if tif not in data['Name']:
                                                        if tiff not in data['Name']:
                                                            if raw not in data['Name']:
                                                                if jpeg not in data['Name']:
                                                                    if img not in data['Name']:
                                                                        if viw not in data['Name']:
                                                                            OFC.delete(self, data['Name'])
            else:
                pass

        if countber == '1':
            jpg = b'jpg'
            bmp = b'bmp'
            rle = b'rle'
            dib = b'dib'
            gif = b'gif'
            png = b'png'
            tif = b'tif'
            tiff = b'tiff'
            raw = b'raw'
            jpeg = b'jpeg'
            img = b'img'
            body = b'BodyText'
            xml = b'XML Template'
            doc = b'DocHistory'
            viw = b'ViewText'
            for data in self.ALL_Array:
                if data['Name'] not in b'FileHeader' b'_HwpSuSignaturearyInformation' b'PrvImage' b'PrvText' b'DocOptions':
                    if data['Name'] not in b'DocInfo' b'Scripts' b'Scripts/JScriptVersion':
                        if data['Name'] not in b'Scripts/DefaultJScript' b'BinData' b'DocOptions/_LinkDoc':
                            if body not in data['Name']:
                                if jpg not in data['Name']:
                                    if bmp not in data['Name']:
                                        if rle not in data['Name']:
                                            if dib not in data['Name']:
                                                if gif not in data['Name']:
                                                    if png not in data['Name']:
                                                        if tif not in data['Name']:
                                                            if tiff not in data['Name']:
                                                                if raw not in data['Name']:
                                                                    if jpeg not in data['Name']:
                                                                        if img not in data['Name']:
                                                                            if xml not in data['Name']:
                                                                                if doc not in data['Name']:
                                                                                    if viw not in data['Name']:
                                                                                        OFC.delete(self, data['Name'])
            else:
                pass
# =======================================================================================


# ======================================= CDR ===========================================
class Ofcwrite:
    def __init__(self, Signature, Ofc_Array, BBAT_Size, SBAT_Size, BBAT, BBAT_Array, SBAT, SBAT_fat, Root_Chain, SBAT_Sector):
        self.Signature = Signature
        self.Ofc_Array = Ofc_Array
        self.BBAT_Size = BBAT_Size
        self.SBAT_Size = SBAT_Size
        self.BBAT = BBAT
        self.BBAT_Array = BBAT_Array
        self.SBAT = SBAT
        self.SBAT_fat = SBAT_fat
        self.Root_Chain = Root_Chain
        self.SBAT_Sector = SBAT_Sector

    def Root_Node(self, node):
        for i, Ofc_Array in enumerate(self.Ofc_Array):
            if Ofc_Array['Left'] == node or Ofc_Array['Right'] == node or Ofc_Array['Child'] == node:
                return i

    def Max_Node(self, node):
        tn = node
        while True:
            Ofc_Array = self.Ofc_Array[tn]
            if Ofc_Array['Right'] == 0xffffffff:
                break
            else:
                tn = Ofc_Array['Right']
        return tn

    def delete(self, del_no):
        del_Ofc_Array = self.Ofc_Array[del_no]
        left_tmp = del_Ofc_Array['Left']
        right_tmp = del_Ofc_Array['Right']
        child_tmp = del_Ofc_Array['Child']
        root_tmp = self.Root_Node(del_no)
        if left_tmp != 0xffffffff and right_tmp != 0xffffffff:
            tn = left_tmp
            Blank = self.Max_Node(left_tmp)
            self.Ofc_header(Blank, Ofc_Array_right=right_tmp)

        elif left_tmp != 0xffffffff and right_tmp == 0xffffffff:
            tn = left_tmp

        elif left_tmp == 0xffffffff and right_tmp != 0xffffffff:
            tn = right_tmp

        else:
            tn = 0xffffffff

        Ofc_Array = self.Ofc_Array[root_tmp]
        if Ofc_Array['Left'] == del_no:
            self.Ofc_header(root_tmp, Ofc_Array_left=tn)
        elif Ofc_Array['Right'] == del_no:
            self.Ofc_header(root_tmp, Ofc_Array_right=tn)
        else:
            self.Ofc_header(root_tmp, Ofc_Array_dir=tn)
        self.Ofc_header(del_no, size=0, start=0xffffffff, Ofc_Array_left=0xffffffff, Ofc_Array_right=0xffffffff,
                              Ofc_Array_dir=0xffffffff, del_info=True)
        return self.Signature

    def write(self, tn, data):
        ofc_start = self.Ofc_Array[tn]['Start']
        ofc_size = self.Ofc_Array[tn]['Size']
        if len(data) >= 0x1000:
            if ofc_size >= 0x1000:
                if ofc_size >= len(data):
                    n = (len(data) / self.BBAT_Size) + (1 if (len(data) % self.BBAT_Size) else 0)
                    tmp_data = data + ('\x00' * ((n * self.BBAT_Size) - len(data)))
                    tmp_chian = Sector_Chain(ofc_start, self.BBAT_Array)
                    tmp_chian = self.Reduce_BBAT_Chain(tmp_chian, n)
                    self.BBAT_Write_Chain(tmp_data, tmp_chian)
                    self.Ofc_header(tn, size=len(data))
                else:
                    n = (len(data) / self.BBAT_Size) + (1 if (len(data) % self.BBAT_Size) else 0)
                    tmp_data = data + ('\x00' * ((n * self.BBAT_Size) - len(data)))
                    tmp_chian = Sector_Chain(ofc_start, self.BBAT_Array)
                    tmp_count = 0
                    if (len(tmp_chian) * self.BBAT_Size) < len(tmp_data):
                        tmp_size = len(tmp_data) - (len(tmp_chian) * self.BBAT_Size)
                        tmp_count = (tmp_size / self.BBAT_Size) + (1 if (tmp_size % self.BBAT_Size) else 0)
                        self.Add_BBAT_Count(tmp_count)
                    tmp_chian = self.Modify_BBAT_Chain(tmp_chian, tmp_count)
                    self.BBAT_Write_Chain(tmp_data, tmp_chian)
                    self.Ofc_header(tn, size=len(data))
            else:
                n = (len(data) / self.BBAT_Size) + (1 if (len(data) % self.BBAT_Size) else 0)
                tmp_data = data + ('\x00' * ((n * self.BBAT_Size) - len(data)))
                tmp_count = len(tmp_data) / self.BBAT_Size
                self.Add_BBAT_Count(tmp_count)
                tmp_chian = self.Modify_BBAT_Chain(None, tmp_count)
                self.BBAT_Write_Chain(tmp_data, tmp_chian)
                self.Ofc_header(tn, size=len(data), start=tmp_chian[0])
                tmp_chian = Sector_Chain(ofc_start, self.SBAT_fat)
                SBAT = self.SBAT
                for tn in tmp_chian:
                    SBAT = SBAT[:tn * 4] + '\xff\xff\xff\xff' + SBAT[(tn + 1) * 4:]
                self.Modify_SBAT(SBAT)

        else:
            if ofc_size >= 0x1000:
                n = (len(data) / self.SBAT_Size) + (1 if (len(data) % self.SBAT_Size) else 0)
                tmp_data = data + ('\x00' * ((n * self.SBAT_Size) - len(data)))
                tmp_count = len(tmp_data) / self.SBAT_Size
                self.Add_SBAT_Count(tmp_count)
                tmp_chian = self.Modify_SBAT_Chain(None, tmp_count)
                Chain_Array, _, _, _ = Sector_Chain_Array(self.Signature)
                self.BBAT = ''
                for i in range(len(Chain_Array) / 4):
                    n = c_uint32(Chain_Array, i * 4)
                    self.BBAT += Reader_ID(self.Signature, n, self.BBAT_Size)
                self.SBAT_Sector = Sector_Chain(self.Ofc_Array[0]['Start'], self.BBAT_Array)
                self.SBAT_write_Chain(tmp_data, tmp_chian)
                self.Ofc_header(tn, size=len(data), start=tmp_chian[0])
                tmp_chian = Sector_Chain(ofc_start, self.BBAT_Array)
                BBAT = self.BBAT
                for tn in tmp_chian:
                    BBAT = BBAT[:tn * 4] + '\xff\xff\xff\xff' + BBAT[(tn + 1) * 4:]
                self.Modify_BBAT(BBAT)

            else:
                if ofc_size >= len(data):
                    n = (len(data) / self.SBAT_Size) + (1 if (len(data) % self.SBAT_Size) else 0)
                    tmp_data = data + ('\x00' * ((n * self.SBAT_Size) - len(data)))
                    tmp_chian = Sector_Chain(ofc_start, self.SBAT_fat)
                    tmp_chian = self.Reduce_SBAT_Chain(tmp_chian, n)
                    self.SBAT_write_Chain(tmp_data, tmp_chian)
                    self.Ofc_header(tn, size=len(data))
                else:
                    n = (len(data) / self.SBAT_Size) + (1 if (len(data) % self.SBAT_Size) else 0)
                    tmp_data = data + ('\x00' * ((n * self.SBAT_Size) - len(data)))
                    tmp_chian = Sector_Chain(ofc_start, self.SBAT_fat)
                    tmp_count = 0
                    if (len(tmp_chian) * self.SBAT_Size) < len(tmp_data):
                        tmp_size = len(tmp_data) - (len(tmp_chian) * self.SBAT_Size)
                        tmp_count = (tmp_size / self.SBAT_Size) + (1 if (tmp_size % self.SBAT_Size) else 0)
                        self.Add_SBAT_Count(tmp_count)
                    tmp_chian = self.Modify_SBAT_Chain(tmp_chian, tmp_count)
                    self.BBAT_Array = {}
                    for i in range(len(self.BBAT) / 4):
                        n = c_uint32(self.BBAT, i * 4)
                        self.BBAT_Array[i] = n
                    self.SBAT_Sector = Sector_Chain(self.Ofc_Array[0]['Start'], self.BBAT_Array)
                    self.SBAT_write_Chain(tmp_data, tmp_chian)
                    self.Ofc_header(tn, size=len(data))
        return self.Signature

    def BBAT_Write_Chain(self, tmp_data, tmp_chian):
        for i, n in tmp_chian:
            off = (n + 1) * self.BBAT_Size
            self.Signature = self.Signature[:off] + tmp_data[i * self.BBAT_Size:(i + 1) * self.BBAT_Size] + self.Signature[off + self.BBAT_Size:]

    def SBAT_write_Chain(self, tmp_data, tmp_chian):
        for i, n in tmp_chian:
            off = (self.SBAT_Sector[n / 8] + 1) * self.BBAT_Size
            off += (n % 8) * self.SBAT_Size
            self.Signature = self.Signature[:off] + tmp_data[i * self.SBAT_Size:(i + 1) * self.SBAT_Size] + self.Signature[off + self.SBAT_Size:]

    def BBAT_write(self, tn, data):
        off = (tn + 1) * self.BBAT_Size
        if len(data) == self.BBAT_Size:
            self.Signature = self.Signature[:off] + data + self.Signature[off + self.BBAT_Size:]
            return True
        return False

    def Ofc_header(self, node, size=None, start=None, Ofc_Array_left=None, Ofc_Array_right=None, Ofc_Array_dir=None, del_info=False):
        n = self.Root_Chain[int(node / 4)]
        buf = Reader_ID(self.Signature, n, self.BBAT_Size)
        off = ((node % 4) * 0x80)
        if del_info and off == 0x180:
            buf = buf[:off] + b'\x00' * 0x80
        elif del_info:
            buf = buf[:off] + b'\x00' * 0x80 + buf[off + 0x80:]
        if size is not None:
            t_off = off + 0x78
            buf = buf[:t_off] + struct.pack('<L', size) + buf[t_off + 4:]
        if start is not None:
            t_off = off + 0x74
            buf = buf[:t_off] + struct.pack('<L', start) + buf[t_off + 4:]
        if Ofc_Array_left is not None:
            t_off = off + 0x44
            buf = buf[:t_off] + struct.pack('<L', Ofc_Array_left) + buf[t_off + 4:]
        if Ofc_Array_right is not None:
            t_off = off + 0x48
            buf = buf[:t_off] + struct.pack('<L', Ofc_Array_right) + buf[t_off + 4:]
        if Ofc_Array_dir is not None:
            t_off = off + 0x4C
            buf = buf[:t_off] + struct.pack('<L', Ofc_Array_dir) + buf[t_off + 4:]
        self.BBAT_write(n, buf)

    def Reduce_SBAT_Chain(self, chain_list, count_chain):
        if len(chain_list) > count_chain:
            tmp_chian = []
            for i in range(len(self.SBAT) / 4):
                tmp_chian.append(c_uint32(self.SBAT, i * 4))
            tmp = chain_list[count_chain:]
            chain_list = chain_list[:count_chain]
            tmp_chian[tmp[0]] = 0xfffffffe
            for i in tmp[1:]:
                tmp_chian[i] = 0xffffffff
            self.SBAT = ''
            for i in tmp_chian:
                self.SBAT += struct.pack('<L', i)
            SBAT_Start_Sector = c_uint32(self.Signature, 0x3c)
            SBAT_Chain = Sector_Chain(SBAT_Start_Sector, self.BBAT_Array)
            for i, n in SBAT_Chain:
                self.BBAT_write(n, self.SBAT[i * self.BBAT_Size:(i + 1) * self.BBAT_Size])
            return chain_list
        elif len(chain_list) == count_chain:
            return chain_list
        else:
            raise Error('Invalid call')

    def Reduce_BBAT_Chain(self, chain_list, count_chain):
        if len(chain_list) > count_chain:
            tmp_chian = []
            for i in range(len(self.BBAT) / 4):
                tmp_chian.append(c_uint32(self.BBAT, i * 4))
            tmp = chain_list[count_chain:]
            chain_list = chain_list[:count_chain]
            tmp_chian[tmp[0]] = 0xfffffffe
            for i in tmp[1:]:
                tmp_chian[i] = 0xffffffff
            self.BBAT = ''
            for i in tmp_chian:
                self.BBAT += struct.pack('<L', i)
            tmp, BBAT_Count, Extra_Count, Extra_Strat = \
                Sector_Chain_Array(self.Signature)
            Chain_Array = []
            for i in range(len(tmp) / 4):
                Chain_Array.append(c_uint32(tmp, i * 4))
            for i, n in Chain_Array:
                self.BBAT_write(n, self.BBAT[i * self.BBAT_Size:(i + 1) * self.BBAT_Size])
            return chain_list
        elif len(chain_list) == count_chain:
            return chain_list
        else:
            raise Error('Invalid call')

    def Add_BBAT_Count(self, count):
        size = (len(self.Signature) / self.BBAT_Size) * self.BBAT_Size
        self.Signature = self.Signature[:size]
        attach_data = self.Signature[size:]
        Chain_Array, BBAT_Count, _, _ = Sector_Chain_Array(self.Signature)
        BBAT = ''
        for i in range(BBAT_Count):
            tn = c_uint32(Chain_Array, i * 4)
            BBAT += Reader_ID(self.Signature, tn, self.BBAT_Size)
        BBAT_chain = []
        for i in range(len(BBAT) / 4):
            BBAT_chain.append(c_uint32(BBAT, i * 4))
        free_chain = [i for i, tn in BBAT_chain if (tn == 0xffffffff and i < size / self.BBAT_Size)]

        if len(free_chain) >= count:
            return
        stn = (size / self.BBAT_Size) - 2
        n = (len(self.BBAT) / 4 - 1) - stn
        if n >= count:
            self.Signature += '\x00' * self.BBAT_Size * count
            self.Signature += attach_data
        else:
            Special = []
            extra_data = ''
            # bbat_data = ''
            # add_data = ''

            add_count = count - n
            add_data = ('\x00' * self.BBAT_Size * add_count)
            bbat_count = (add_count / (self.BBAT_Size / 4)) + (1 if (add_count % (self.BBAT_Size / 4)) else 0)
            pre_count_BBAT = c_uint32(self.Signature, 0x2c)
            Extra_Strat = c_uint32(self.Signature, 0x44)
            Extra_Count = c_uint32(self.Signature, 0x48)
            pre_bbat_count = bbat_count
            while True:
                if pre_count_BBAT + bbat_count > 109:
                    tmp_count = (pre_count_BBAT + bbat_count - 109)
                    total_extra = (tmp_count / ((self.BBAT_Size - 4) / 4)) + (1 if (tmp_count % ((self.BBAT_Size - 4) / 4)) else 0)
                    x_count = total_extra - Extra_Count
                    add_count += x_count
                    bbat_count = (add_count / (self.BBAT_Size / 4)) + (1 if (add_count % (self.BBAT_Size / 4)) else 0)
                if pre_bbat_count == bbat_count:
                    break
                else:
                    pre_bbat_count = bbat_count
            total_BBAT_count = pre_count_BBAT + bbat_count
            self.Signature = self.Signature[:0x2c] + struct.pack('<L', total_BBAT_count) + self.Signature[0x30:]
            stn += 1
            if total_BBAT_count > 109:
                tmp_count = (total_BBAT_count - 109)
                total_extra = (tmp_count / ((self.BBAT_Size - 4) / 4)) + (1 if (tmp_count % ((self.BBAT_Size - 4) / 4)) else 0)
                x_count = total_extra - Extra_Count
                if Extra_Count == 0:
                    data = struct.pack('<LL', stn, total_extra)
                    self.Signature = self.Signature[:0x44] + data + self.Signature[0x4C:]
                else:
                    data = struct.pack('<L', total_extra)
                    self.Signature = self.Signature[:0x48] + data + self.Signature[0x4C:]
                next_b = Extra_Strat
                if Extra_Count == 1:
                    tmp_data = Reader_ID(self.Signature, next_b, self.BBAT_Size)
                else:
                    tmp_data = ''
                    for i in range(Extra_Count - 1):
                        tmp_data = Reader_ID(self.Signature, next_b, self.BBAT_Size)
                        next_b = c_uint32(tmp_data, self.BBAT_Size - 4)
                tmp_data = tmp_data[:-4] + struct.pack('<L', stn)
                off = (next_b + 1) * self.BBAT_Size
                self.Signature = self.Signature[:off] + tmp_data + self.Signature[off + self.BBAT_Size:]
                for i in range(x_count):
                    extra_data += '\xff\xff\xff\xff' * ((self.BBAT_Size / 4) - 1)
                    if i != (x_count - 1):
                        extra_data += struct.pack('<L', stn + 1)
                    else:
                        extra_data += '\xfe\xff\xff\xff'
                    Special.append(stn)
                    stn += 1
            BBAT_no = []
            bbat_data = '\xff' * self.BBAT_Size * bbat_count
            for i in range(bbat_count):
                BBAT_no.append(stn)
                stn += 1
            self.Signature += extra_data + bbat_data + add_data + attach_data
            Special += BBAT_no
            Chain_Array, BBAT_Count, _, _ = Sector_Chain_Array(self.Signature)
            bbbat_count = (self.BBAT_Size / 4)
            for tn in Special:
                seg = tn / bbbat_count
                off = tn % bbbat_count
                tn = c_uint32(Chain_Array, seg * 4)
                t_off = ((tn + 1) * self.BBAT_Size) + (off * 4)
                self.Signature = self.Signature[:t_off] + '\xfd\xff\xff\xff' + self.Signature[t_off + 4:]
            for i, tn in BBAT_no:
                off = Sector_Chain_Array_Off(self.Signature, pre_count_BBAT + i)
                self.Signature = (self.Signature[:off] + struct.pack('<L', tn) + self.Signature[off + 4:])

    def Add_SBAT_Count(self, count):
        Root = self.Ofc_Array[0]
        root_size = Root['Size']
        root_start = Root['Start']
        SBAT_chain = []
        for i in range(len(self.SBAT) / 4):
            SBAT_chain.append(c_uint32(self.SBAT, i * 4))
        free_chain = [i for i, tn in SBAT_chain if (tn == 0xffffffff and i < root_size / self.SBAT_Size)]
        if len(free_chain) >= count:
            return
        else:
            size = count * self.SBAT_Size
            add_big_count = (size / self.BBAT_Size) + (1 if (size % self.BBAT_Size) else 0)
            self.Add_BBAT_Count(add_big_count)
            tmp_chian = Sector_Chain(root_start, self.BBAT_Array)
            self.Modify_BBAT_Chain(tmp_chian, add_big_count)
            self.Ofc_header(0, size=root_size + add_big_count * self.BBAT_Size)

    def Modify_BBAT_Chain(self, pre_chain, add_count):
        if add_count < 0:
            return []
        Chain_Array, BBAT_Count, _, _ = Sector_Chain_Array(self.Signature)
        BBAT = ''
        for i in range(BBAT_Count):
            tn = c_uint32(Chain_Array, i * 4)
            BBAT += Reader_ID(self.Signature, tn, self.BBAT_Size)
        BBAT_chain = []
        for i in range(len(BBAT) / 4):
            BBAT_chain.append(c_uint32(BBAT, i * 4))
        free_chain = [i for i, tn in BBAT_chain if (tn == 0xffffffff)]
        if pre_chain:
            retmp_chian = pre_chain + free_chain[:add_count]
            tmp_chian = pre_chain[-1:] + free_chain[:add_count]
        else:
            retmp_chian = free_chain[:add_count]
            tmp_chian = free_chain[:add_count]
        for i in range(len(tmp_chian) - 1):
            tn = tmp_chian[i + 1]
            data = struct.pack('<L', tn)
            tn = tmp_chian[i]
            BBAT = BBAT[:tn * 4] + data + BBAT[(tn + 1) * 4:]
        tn = tmp_chian[-1]
        BBAT = BBAT[:tn * 4] + '\xfe\xff\xff\xff' + BBAT[(tn + 1) * 4:]
        self.Modify_BBAT(BBAT)
        return retmp_chian

    def Modify_SBAT_Chain(self, pre_chain, add_count):
        if add_count < 0:
            return []
        SBAT = self.SBAT
        SBAT_chain = []
        for i in range(len(SBAT) / 4):
            SBAT_chain.append(c_uint32(SBAT, i * 4))
        free_chain = [i for i, tn in SBAT_chain if (tn == 0xffffffff)]
        if pre_chain:
            retmp_chian = pre_chain + free_chain[:add_count]
            tmp_chian = pre_chain[-1:] + free_chain[:add_count]
        else:
            retmp_chian = free_chain[:add_count]
            tmp_chian = free_chain[:add_count]
        for i in range(len(tmp_chian) - 1):
            tn = tmp_chian[i + 1]
            data = struct.pack('<L', tn)
            tn = tmp_chian[i]
            SBAT = SBAT[:tn * 4] + data + SBAT[(tn + 1) * 4:]
        tn = tmp_chian[-1]
        SBAT = SBAT[:tn * 4] + '\xfe\xff\xff\xff' + SBAT[(tn + 1) * 4:]
        n = len(SBAT) % self.BBAT_Size
        if n:
            tmp = self.BBAT_Size - n
            SBAT += '\xff' * tmp
        self.Modify_SBAT(SBAT)
        return retmp_chian

    def Modify_SBAT(self, SBAT):
        SBAT_no = c_uint32(self.Signature, 0x3c)
        SBAT_Chain = Sector_Chain(SBAT_no, self.BBAT_Array)
        for i, tn in SBAT_Chain:
            data = SBAT[i * self.BBAT_Size:(i + 1) * self.BBAT_Size]
            off = (tn + 1) * self.BBAT_Size
            self.Signature = self.Signature[:off] + data + self.Signature[off + self.BBAT_Size:]

    def Modify_BBAT(self, BBAT):
        self.BBAT = BBAT
        Chain_Array, _, _, _ = Sector_Chain_Array(self.Signature)
        for i in range(len(Chain_Array) / 4):
            tn = c_uint32(Chain_Array, i * 4)
            data = BBAT[i * self.BBAT_Size:(i + 1) * self.BBAT_Size]
            off = (tn + 1) * self.BBAT_Size
            self.Signature = self.Signature[:off] + data + self.Signature[off + self.BBAT_Size:]
# ====================================================================================================

def my_exception_hook(exctype, value, traceback):
    sys._excepthook(exctype, value, traceback)


if __name__ == '__main__':
    loopexit = QApplication(sys.argv)
    instance = cdrgui()
    loopexit.setStyleSheet(style)
    sys._excepthook = sys.excepthook
    sys.excepthook = my_exception_hook
    loopexit.exec_()
