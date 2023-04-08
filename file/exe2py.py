from __future__ import print_function
import tkinter
from tkinter import END
import tkinter.filedialog
import tkinter.messagebox
import os
import struct
import marshal
import zlib
import sys
from uuid import uuid4 as uniquename

if sys.version_info.major != 3:
    tkinter.messagebox.showerror("Error!", "uncompyle6 不支持 Python2")
    tkinter.messagebox.showinfo("Tips", "Exiting...")
    sys.exit()
elif sys.version_info.minor > 8:
    tkinter.messagebox.showwarning("Warning!", "uncompyle6 不支持 Python3.9+ 如果要支持请自行修改源代码!")
    tkinter.messagebox.showinfo("Tips", "Exiting...")
    sys.exit()
else:
    tkinter.messagebox.showinfo("Info!", f"uncompyle6 可能支持 Python{sys.version_info.major}{sys.version_info.minor}, 含有不确定性! "
                                         f"最好是封装时的原版本!")

try:
    import uncompyle6
except ImportError:
    os.system("pip install uncompyle6")
    import uncompyle6
from uncompyle6 import decompile_file


class CTOCEntry:
    def __init__(self, position, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name):
        self.position = position
        self.cmprsdDataSize = cmprsdDataSize
        self.uncmprsdDataSize = uncmprsdDataSize
        self.cmprsFlag = cmprsFlag
        self.typeCmprsData = typeCmprsData
        self.name = name


class PyInstArchive:
    PYINST20_COOKIE_SIZE = 24  # For pyinstaller 2.0
    PYINST21_COOKIE_SIZE = 24 + 64  # For pyinstaller 2.1+
    MAGIC = b'MEI\014\013\012\013\016'  # Magic number which identifies pyinstaller

    def __init__(self, path):
        self.filePath = path
        self.pycMagic = b'\0' * 4
        self.barePycList = []  # List of pyc's whose headers have to be fixed

    def open(self):
        try:
            self.fPtr = open(self.filePath, 'rb')
            self.fileSize = os.stat(self.filePath).st_size
        except:
            print('[!] 错误 : 不能打开 {0}'.format(self.filePath))
            return False
        return True

    def close(self):
        try:
            self.fPtr.close()
        except:
            pass

    def checkFile(self):
        print('[+] 正在解包 {0}'.format(self.filePath))

        searchChunkSize = 8192
        endPos = self.fileSize
        self.cookiePos = -1

        if endPos < len(self.MAGIC):
            print('[!] 错误 : 文件太短或被截断')
            return False

        while True:
            startPos = endPos - searchChunkSize if endPos >= searchChunkSize else 0
            chunkSize = endPos - startPos

            if chunkSize < len(self.MAGIC):
                break

            self.fPtr.seek(startPos, os.SEEK_SET)
            data = self.fPtr.read(chunkSize)

            offs = data.rfind(self.MAGIC)

            if offs != -1:
                self.cookiePos = startPos + offs
                break

            endPos = startPos + len(self.MAGIC) - 1

            if startPos == 0:
                break

        if self.cookiePos == -1:
            print('[!] 错误:缺少cookie、不支持的Pyinstaller版本或不是Pyinstaller存档 ')
            return False

        self.fPtr.seek(self.cookiePos + self.PYINST20_COOKIE_SIZE, os.SEEK_SET)

        if b'python' in self.fPtr.read(64).lower():
            print('[+] Pyinstaller 版本: 2.1+')
            self.pyinstVer = 21  # pyinstaller 2.1+
        else:
            self.pyinstVer = 20  # pyinstaller 2.0
            print('[+] Pyinstaller 版本: 2.0')

        return True

    def getCArchiveInfo(self):
        global toc, tocLen, lengthofPackage, pyver
        try:
            if self.pyinstVer == 20:
                self.fPtr.seek(self.cookiePos, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, pyver) = \
                    struct.unpack('!8siiii', self.fPtr.read(self.PYINST20_COOKIE_SIZE))

            elif self.pyinstVer == 21:
                self.fPtr.seek(self.cookiePos, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, pyver, pylibname) = \
                    struct.unpack('!8sIIii64s', self.fPtr.read(self.PYINST21_COOKIE_SIZE))

        except:
            print('[!] 错误 : 文件不是Pyinstaller存档')
            return False

        self.pymaj, self.pymin = (pyver // 100, pyver % 100) if pyver >= 100 else (pyver // 10, pyver % 10)
        print('[+] Python 版本: {0}.{1}'.format(self.pymaj, self.pymin))

        # Additional data after the cookie
        tailBytes = self.fileSize - self.cookiePos - (
            self.PYINST20_COOKIE_SIZE if self.pyinstVer == 20 else self.PYINST21_COOKIE_SIZE)

        # Overlay is the data appended at the end of the PE
        self.overlaySize = lengthofPackage + tailBytes
        self.overlayPos = self.fileSize - self.overlaySize
        self.tableOfContentsPos = self.overlayPos + toc
        self.tableOfContentsSize = tocLen

        print('[+] 包长度 : {0} 字节'.format(lengthofPackage))
        return True

    def parseTOC(self):
        # Go to the table of contents
        self.fPtr.seek(self.tableOfContentsPos, os.SEEK_SET)

        self.tocList = []
        parsedLen = 0

        # Parse table of contents
        while parsedLen < self.tableOfContentsSize:
            (entrySize,) = struct.unpack('!i', self.fPtr.read(4))
            nameLen = struct.calcsize('!iIIIBc')

            (entryPos, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name) = \
                struct.unpack(
                    '!IIIBc{0}s'.format(entrySize - nameLen),
                    self.fPtr.read(entrySize - 4))

            name = name.decode('utf-8').rstrip('\0')
            if len(name) == 0:
                name = str(uniquename())
                print('[!] 警告 : 在CArchive中找到了未修改的文件。使用随机名称  {0}'.format(name))

            self.tocList.append(
                CTOCEntry(
                    self.overlayPos + entryPos,
                    cmprsdDataSize,
                    uncmprsdDataSize,
                    cmprsFlag,
                    typeCmprsData,
                    name
                ))

            parsedLen += entrySize
        print('[+] 在CArchive中找到 {0} 个文件 '.format(len(self.tocList)))

    def _writeRawData(self, filepath, data):
        nm = filepath.replace('\\', os.path.sep).replace('/', os.path.sep).replace('..', '__')
        nmDir = os.path.dirname(nm)
        if nmDir != '' and not os.path.exists(nmDir):  # Check if path exists, create if not
            os.makedirs(nmDir)

        with open(nm, 'wb') as f:
            f.write(data)

    def extractFiles(self):
        print('[+] 正在开始提取…请稍候 ')
        extractionDir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.getcwd()))), os.path.basename(self.filePath) + '_extracted')

        if not os.path.exists(extractionDir):
            os.mkdir(extractionDir)

        os.chdir(extractionDir)

        for entry in self.tocList:
            self.fPtr.seek(entry.position, os.SEEK_SET)
            data = self.fPtr.read(entry.cmprsdDataSize)

            if entry.cmprsFlag == 1:
                data = zlib.decompress(data)
                # Malware may tamper with the uncompressed size
                # Comment out the assertion in such a case
                assert len(data) == entry.uncmprsdDataSize  # Sanity Check

            if entry.typeCmprsData == b'd' or entry.typeCmprsData == b'o':
                # d -> ARCHIVE_ITEM_DEPENDENCY
                # o -> ARCHIVE_ITEM_RUNTIME_OPTION
                # These are runtime options, not files
                continue

            basePath = os.path.dirname(entry.name)
            if basePath != '':
                # Check if path exists, create if not
                if not os.path.exists(basePath):
                    os.makedirs(basePath)

            if entry.typeCmprsData == b's':
                # s -> ARCHIVE_ITEM_PYSOURCE
                # Entry point are expected to be python scripts
                print('[+] 可能的入口点 : {0}.pyc'.format(entry.name))

                if self.pycMagic == b'\0' * 4:
                    # if we don't have the pyc header yet, fix them in a later pass
                    self.barePycList.append(entry.name + '.pyc')
                self._writePyc(entry.name + '.pyc', data)

            elif entry.typeCmprsData == b'M' or entry.typeCmprsData == b'm':
                # M -> ARCHIVE_ITEM_PYPACKAGE
                # m -> ARCHIVE_ITEM_PYMODULE
                # packages and modules are pyc files with their header intact

                # From PyInstaller 5.3 and above pyc headers are no longer stored
                # https://github.com/pyinstaller/pyinstaller/commit/a97fdf
                if data[2:4] == b'\r\n':
                    # < pyinstaller 5.3
                    if self.pycMagic == b'\0' * 4:
                        self.pycMagic = data[0:4]
                    self._writeRawData(entry.name + '.pyc', data)

                else:
                    # >= pyinstaller 5.3
                    if self.pycMagic == b'\0' * 4:
                        # if we don't have the pyc header yet, fix them in a later pass
                        self.barePycList.append(entry.name + '.pyc')

                    self._writePyc(entry.name + '.pyc', data)

            else:
                self._writeRawData(entry.name, data)

                if entry.typeCmprsData == b'z' or entry.typeCmprsData == b'Z':
                    self._extractPyz(entry.name)

        # Fix bare pyc's if any
        self._fixBarePycs()

    def _fixBarePycs(self):
        for pycFile in self.barePycList:
            with open(pycFile, 'r+b') as pycFile:
                # Overwrite the first four bytes
                pycFile.write(self.pycMagic)

    def _writePyc(self, filename, data):
        with open(filename, 'wb') as pycFile:
            pycFile.write(self.pycMagic)  # pyc magic

            if self.pymaj >= 3 and self.pymin >= 7:  # PEP 552 -- Deterministic pycs
                pycFile.write(b'\0' * 4)  # Bitfield
                pycFile.write(b'\0' * 8)  # (Timestamp + size) || hash

            else:
                pycFile.write(b'\0' * 4)  # Timestamp
                if self.pymaj >= 3 and self.pymin >= 3:
                    pycFile.write(b'\0' * 4)  # Size parameter added in Python 3.3

            pycFile.write(data)

    def _extractPyz(self, name):
        dirName = name + '_extracted'
        # Create a directory for the contents of the pyz
        if not os.path.exists(dirName):
            os.mkdir(dirName)

        with open(name, 'rb') as f:
            pyzMagic = f.read(4)
            assert pyzMagic == b'PYZ\0'  # Sanity Check

            pyzPycMagic = f.read(4)  # Python magic value

            if self.pycMagic == b'\0' * 4:
                self.pycMagic = pyzPycMagic

            elif self.pycMagic != pyzPycMagic:
                self.pycMagic = pyzPycMagic
                print('[!] 警告 : PYZ存档中文件的PycMagic与CArchive中的不同 ')

            # Skip PYZ extraction if not running under the same python version
            if self.pymaj != sys.version_info.major or self.pymin != sys.version_info.minor:
                print(
                    '[!] 警告 : 此脚本运行的Python版本与用于生成可执行文件的Python版本不同。')
                print(
                    '[!] 请在Python {0}.{1}中运行此脚本,防止在解包过程中出现提取错误 '.format(
                        self.pymaj, self.pymin))
                print('[!] 正在跳过PYZ提取')
                return

            (tocPosition,) = struct.unpack('!i', f.read(4))
            f.seek(tocPosition, os.SEEK_SET)

            try:
                toc = marshal.load(f)
            except:
                print('[!] 取消分组失败。无法提取{0}。正在提取剩余文件。 '.format(name))
                return

            print('[+] 在PYZ存档中找到 {0} 个文件 '.format(len(toc)))

            # From pyinstaller 3.1+ toc is a list of tuples
            if type(toc) == list:
                toc = dict(toc)

            for key in toc.keys():
                (ispkg, pos, length) = toc[key]
                f.seek(pos, os.SEEK_SET)
                fileName = key

                try:
                    # for Python > 3.3 some keys are bytes object some are str object
                    fileName = fileName.decode('utf-8')
                except:
                    pass

                # Prevent writing outside dirName
                fileName = fileName.replace('..', '__').replace('.', os.path.sep)

                if ispkg == 1:
                    filePath = os.path.join(dirName, fileName, '__init__.pyc')

                else:
                    filePath = os.path.join(dirName, fileName + '.pyc')

                fileDir = os.path.dirname(filePath)
                if not os.path.exists(fileDir):
                    os.makedirs(fileDir)

                try:
                    data = f.read(length)
                    data = zlib.decompress(data)
                except:
                    print('[!] 错误：未能解压缩 {0}，可能已加密。按原样提取.'.format(filePath))
                    open(filePath + '.encrypted', 'wb').write(data)
                else:
                    self._writePyc(filePath, data)


def choose_file():
    global filepath, Entry1, String
    filepath = tkinter.filedialog.askopenfile(mode="r", title="选择Exe文件", filetypes=[("可执行文件", "*.exe")],
                                              defaultextension="*.exe")
    String.set(filepath.name)


def choose_file1():
    global filepath, Entry1, String
    filepath = tkinter.filedialog.asksaveasfile(title="选择Exe文件", filetypes=[("Python文件", "*.py")],
                                                defaultextension="*.py")
    String1.set(filepath.name)


class StdoutRedirector(object):
    # 重定向输出类
    def __init__(self, text_widget):
        self.text_space = text_widget
        # 将其备份
        self.stdoutbak = sys.stdout
        self.stderrbak = sys.stderr

    def write(self, str):
        self.text_space.insert(END, str)
        # self.text_space.insert(END, '\n')
        self.text_space.see(END)
        self.text_space.update()

    def restoreStd(self):
        # 恢复标准输出
        sys.stdout = self.stdoutbak
        sys.stderr = self.stderrbak

    def flush(self):
        # 关闭程序时会调用flush刷新缓冲区，没有该函数关闭时会报错
        pass


def conv():
    global top, String2, Entry3
    String2 = tkinter.StringVar()
    arch = PyInstArchive(String.get())
    if arch.open():
        if arch.checkFile():
            if arch.getCArchiveInfo():
                arch.parseTOC()
                arch.extractFiles()
                arch.close()
                print('[+] 已成功提取Pyinstaller存档 : {0}'.format(String.get()))
                print('')
                print('现在，您可以对解压缩目录中的pyc文件使用python反编译器 ')

        arch.close()
    top = tkinter.Tk()
    tkinter.Label(top, text="可能入口文件(加上.pyc)", font=("华文行楷", 20)).pack()
    Entry3 = tkinter.Entry(top, width=30, bd=10, textvariable=String2)
    Entry3.pack()
    tkinter.Button(top, text="OK", font=("华文行楷", 15), command=conv2).pack()


def conv2():
    global Entry3
    file_pyc = os.path.abspath(os.path.dirname(os.path.dirname(os.getcwd()))) + f'/{os.path.basename(Entry1.get()) + "_extracted"}/{Entry3.get()}'

    top.destroy()
    with open(String1.get(), "w") as f:
        decompile_file(file_pyc, f)
        f.close()
    tkinter.messagebox.showinfo("OK", "反编译成功！")


win = tkinter.Tk()
showp = tkinter.Tk(
)
tkinter.Label(showp, text="正在加载……")


String = tkinter.StringVar()
String1 = tkinter.StringVar()

tkinter.Label(win, text="Exe2Py By YanYiGe", font=("华文行楷", 30)).pack()
tkinter.Label(win, text="").pack()
tkinter.Label(win, text="Exe文件路径", font=("华文行楷", 20)).pack()
Entry1 = tkinter.Entry(win, state="readonly", width=30, bd=10, textvariable=String)
Entry1.pack()
tkinter.Button(win, text="选择Exe文件", font=("华文行楷", 15), command=choose_file).pack()
tkinter.Label(win, text="Py文件路径", font=("华文行楷", 20)).pack()
Entry2 = tkinter.Entry(win, state="readonly", width=30, bd=10, textvariable=String1)
Entry2.pack()
tkinter.Button(win, text="选择Py文件", font=("华文行楷", 15), command=choose_file1).pack()

tkinter.Button(win, text="转换！", font=("华文行楷", 25), command=conv).pack()
text = tkinter.Text(win, width=50, height=8)
scroll = tkinter.Scrollbar()
# 放到窗口的右侧, 填充Y竖直方向
scroll.pack(side=tkinter.RIGHT, fill=tkinter.Y)

# 两个控件关联
scroll.config(command=text.yview)
text.config(yscrollcommand=scroll.set)

sys.stdout = StdoutRedirector(text)

text.pack()
tkinter.mainloop()
