## 项目简介

使用pyqt5开发，使用paramiko库连接SSH服务器，使用bcrypt库加密密码，使用cryptography库加密密码，使用PyQt5库开发图形界面。

## 项目文件列表

1. sshdemo.py
   - 最终成品:v3版本
   - 主要功能：连接SSH服务器，获取Nginx状态，启动、停止、重启Nginx，检查Nginx配置，查看访问日志和错误日志，执行命令，编辑文件，设置PIN码，使用PIN码登录。
   - 主要模块：
     - SSHConnectThread：处理SSH连接的线程类。
     - SSHManager：主窗口类，处理用户界面和交互逻辑。
2. sshdemo_PIN码登录.py
   - v2版本 
   - 主要内容：使用PIN码登录的SSH连接和操作。
3. sshdemo_非加密.py
   - v1版本
   - 主要内容：非加密的SSH连接和操作。
4. sshdemo_需求分析报告.md
   - 主要内容：项目概述、需求演进历史、功能需求详细说明。
   - 主要章节：
     - 项目背景：介绍项目的背景和目标。
     - 需求演进历史：描述项目需求的演变过程。
     - 功能需求详细说明：详细描述各个功能需求。
5. requirements.txt
   - 主要内容：项目依赖的第三方库。
6. sshdemo.spec
   - 主要内容：项目打包的配置文件。

## 程序运行与依赖
```shell
python -m venv .venv # 创建虚拟环境
.venv\Scripts\activate # 激活虚拟环境
pip install -r requirements.txt # 安装依赖
python sshdemo.py # 运行程序
```

## 关于打包
1. 安装依赖
```shell
pip install -r requirements.txt
```
2. 打包
```shell
# Windows系统
pyinstaller --clean sshdemo.spec

# 或者直接使用命令行参数打包
pyinstaller --name NginxManager --windowed --icon=nginx.ico --hidden-import paramiko --hidden-import bcrypt --hidden-import cryptography sshdemo.py
```
3. 创建的spec文件
```shell
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['sshdemo.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'paramiko',
        'bcrypt',
        'cryptography',
        'PyQt5',
        'PyQt5.QtCore',
        'PyQt5.QtWidgets'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=block_cipher
)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='NginxManager',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # 不显示控制台窗口
    icon='nginx.ico' if os.path.exists('nginx.ico') else None,
)
```