# 功能：
# 1. 连接SSH服务器
# 2. 获取Nginx状态
# 3. 启动、停止、重启Nginx
# 4. 检查Nginx配置
# 5. 查看访问日志
# 6. 查看错误日志
# 7. 执行命令
# 8. 编辑文件
# 9. 设置PIN码
# 10. 使用PIN码登录

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                           QTextEdit, QMessageBox, QTabWidget, QDialog, QListWidget,
                           QButtonGroup, QDialogButtonBox)
from PyQt5.QtCore import QTimer, Qt, QThread, pyqtSignal
import paramiko
import json
import sys
import os
import hashlib
import secrets
from base64 import b64encode, b64decode

class SSHConnectThread(QThread):
    # 定义信号
    connected = pyqtSignal(bool, str)  # 连接结果信号，参数：是否成功，消息
    status_update = pyqtSignal(str)    # 状态更新信号

    def __init__(self, host, port, username, password):
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.ssh = None

    def run(self):
        try:
            self.status_update.emit('正在连接SSH服务器...')
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # 尝试连接
            ssh.connect(
                self.host,
                port=int(self.port),
                username=self.username,
                password=self.password
            )
            
            # 测试nginx状态
            stdin, stdout, stderr = ssh.exec_command('systemctl status nginx')
            status_output = stdout.read().decode()
            error_output = stderr.read().decode()
            
            if error_output:
                self.connected.emit(False, f'Nginx状态获取失败:\n{error_output}')
                ssh.close()
                return
                
            self.ssh = ssh
            self.connected.emit(True, status_output)
            
        except Exception as e:
            error_msg = str(e)
            if 'Authentication failed' in error_msg:
                msg = '认证失败：用户名或密码错误'
            elif 'Connection refused' in error_msg:
                msg = '连接被拒绝：请检查IP地址和端口是否正确'
            elif 'Network is unreachable' in error_msg:
                msg = '网络不可达：请检查网络连接'
            elif 'Operation timed out' in error_msg:
                msg = '连接超时：请检查服务器是否在线'
            else:
                msg = f'SSH连接失败:\n{error_msg}'
            
            self.connected.emit(False, msg)

class SSHManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ssh = None
        self.config_file = 'ssh_config.json'
        self.pin_file = '.pin_config'
        self.connect_thread = None
        self.salt = self._get_or_create_salt()
        self.initUI()
        self.loadConfig()

    def _get_or_create_salt(self):
        """获取或创建salt"""
        salt_file = '.salt'
        try:
            if os.path.exists(salt_file):
                with open(salt_file, 'rb') as f:
                    return f.read()
            else:
                salt = secrets.token_bytes(16)
                with open(salt_file, 'wb') as f:
                    f.write(salt)
                return salt
        except Exception:
            return b'fixed_salt_value'

    def _hash_value(self, value):
        """对值进行哈希"""
        return hashlib.pbkdf2_hmac(
            'sha256', 
            value.encode(), 
            self.salt, 
            100000
        ).hex()

    def _hash_password(self, password):
        """对密码进行不可逆加密"""
        return hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            self.salt, 
            100000
        ).hex()

    def _encrypt_password(self, password, pin):
        """使用PIN码加密密码"""
        # 使用PIN码生成密钥
        key = hashlib.pbkdf2_hmac(
            'sha256',
            pin.encode(),
            self.salt,
            100000,
            32
        )
        # 简单的XOR加密
        password_bytes = password.encode()
        encrypted = bytearray()
        for i in range(len(password_bytes)):
            encrypted.append(password_bytes[i] ^ key[i % len(key)])
        return b64encode(encrypted).decode()

    def _decrypt_password(self, encrypted, pin):
        """使用PIN码解密密码"""
        try:
            # 使用PIN码生成密钥
            key = hashlib.pbkdf2_hmac(
                'sha256',
                pin.encode(),
                self.salt,
                100000,
                32
            )
            # 解密
            encrypted_bytes = b64decode(encrypted)
            decrypted = bytearray()
            for i in range(len(encrypted_bytes)):
                decrypted.append(encrypted_bytes[i] ^ key[i % len(key)])
            return decrypted.decode()
        except:
            return None

    def setupPIN(self):
        """设置PIN码"""
        dialog = QDialog(self)
        dialog.setWindowTitle('设置PIN码')
        layout = QVBoxLayout(dialog)

        # PIN码输入
        pin_input = QLineEdit()
        pin_input.setEchoMode(QLineEdit.Password)
        pin_input.setPlaceholderText('请输入4-6位PIN码')
        layout.addWidget(QLabel('PIN码:'))
        layout.addWidget(pin_input)

        # 确认PIN码
        pin_confirm = QLineEdit()
        pin_confirm.setEchoMode(QLineEdit.Password)
        pin_confirm.setPlaceholderText('请再次输入PIN码')
        layout.addWidget(QLabel('确认PIN码:'))
        layout.addWidget(pin_confirm)

        # 确认按钮
        btn_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        btn_box.accepted.connect(dialog.accept)
        btn_box.rejected.connect(dialog.reject)
        layout.addWidget(btn_box)

        if dialog.exec_() == QDialog.Accepted:
            pin = pin_input.text()
            if pin == pin_confirm.text() and 4 <= len(pin) <= 6 and pin.isdigit():
                # 保存PIN码的哈希值
                with open(self.pin_file, 'w') as f:
                    f.write(self._hash_value(pin))
                return pin
        return None

    def verifyPIN(self):
        """验证PIN码"""
        dialog = QDialog(self)
        dialog.setWindowTitle('输入PIN码')
        layout = QVBoxLayout(dialog)

        pin_input = QLineEdit()
        pin_input.setEchoMode(QLineEdit.Password)
        pin_input.setPlaceholderText('请输入PIN码')
        layout.addWidget(QLabel('PIN码:'))
        layout.addWidget(pin_input)

        btn_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        btn_box.accepted.connect(dialog.accept)
        btn_box.rejected.connect(dialog.reject)
        layout.addWidget(btn_box)

        if dialog.exec_() == QDialog.Accepted:
            pin = pin_input.text()
            try:
                with open(self.pin_file, 'r') as f:
                    stored_hash = f.read()
                if self._hash_value(pin) == stored_hash:
                    return pin
            except:
                pass
        return None

    def initUI(self):
        self.setWindowTitle('Nginx远程管理工具')
        self.setGeometry(100, 100, 800, 600)
        
        # 创建主窗口部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # SSH连接配置区域
        conn_widget = QWidget()
        conn_layout = QHBoxLayout(conn_widget)
        
        self.ip_input = QLineEdit()
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText('22')  # 添加默认端口提示
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText('root')  # 添加默认用户名提示
        self.password_input = QLineEdit()
        self.pin_input = QLineEdit()  # 添加PIN码输入框
        
        # 设置密码和PIN码输入框的特性
        self.password_input.setEchoMode(QLineEdit.Password)
        self.pin_input.setEchoMode(QLineEdit.Password)
        self.pin_input.setPlaceholderText('PIN码登录')
        
        # 添加输入框变化事件
        self.password_input.textChanged.connect(self.onPasswordChanged)
        self.pin_input.textChanged.connect(self.onPinChanged)
        
        conn_layout.addWidget(QLabel('IP:'))
        conn_layout.addWidget(self.ip_input)
        conn_layout.addWidget(QLabel('端口:'))
        conn_layout.addWidget(self.port_input)
        conn_layout.addWidget(QLabel('用户名:'))
        conn_layout.addWidget(self.username_input)
        conn_layout.addWidget(QLabel('密码:'))
        conn_layout.addWidget(self.password_input)
        conn_layout.addWidget(QLabel('PIN码:'))
        conn_layout.addWidget(self.pin_input)
        
        # 保存连接按钮的引用
        self.connect_btn = QPushButton('连接')
        self.connect_btn.setObjectName('connect_btn')
        self.connect_btn.clicked.connect(self.connectSSH)
        conn_layout.addWidget(self.connect_btn)
        
        # 保存所有输入框的引用
        self.input_widgets = [
            self.ip_input, self.port_input, 
            self.username_input, self.password_input,
            self.pin_input
        ]
        
        layout.addWidget(conn_widget)
        
        # 创建选项卡
        tab_widget = QTabWidget()
        
        # 状态和控制面板
        control_widget = QWidget()
        control_layout = QVBoxLayout(control_widget)
        
        # Nginx控制按钮
        btn_layout = QHBoxLayout()
        start_btn = QPushButton('启动Nginx')
        stop_btn = QPushButton('停止Nginx')
        restart_btn = QPushButton('重启Nginx')
        check_btn = QPushButton('检查配置')
        
        start_btn.clicked.connect(lambda: self.controlNginx('start'))
        stop_btn.clicked.connect(lambda: self.controlNginx('stop'))
        restart_btn.clicked.connect(lambda: self.controlNginx('restart'))
        check_btn.clicked.connect(self.checkNginxConfig)
        
        btn_layout.addWidget(start_btn)
        btn_layout.addWidget(stop_btn)
        btn_layout.addWidget(restart_btn)
        btn_layout.addWidget(check_btn)
        control_layout.addLayout(btn_layout)
        
        # 状态显示
        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        control_layout.addWidget(QLabel('Nginx状态:'))
        control_layout.addWidget(self.status_text)
        
        # 日志选项卡
        log_widget = QWidget()
        log_layout = QVBoxLayout(log_widget)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        
        # 错误日志选项卡
        error_log_widget = QWidget()
        error_log_layout = QVBoxLayout(error_log_widget)
        self.error_log_text = QTextEdit()
        self.error_log_text.setReadOnly(True)
        error_log_layout.addWidget(self.error_log_text)
        
        # 配置编辑选项卡
        config_widget = QWidget()
        config_layout = QVBoxLayout(config_widget)  # 改为垂直布局
        
        # 添加命令输入区域
        cmd_widget = QWidget()
        cmd_layout = QHBoxLayout(cmd_widget)
        
        self.cmd_input = QLineEdit()
        self.cmd_input.setPlaceholderText('输入命令 (例如: vi /etc/nginx/nginx.conf)')
        self.cmd_input.returnPressed.connect(self.executeCommand)  # 按回车执行命令
        
        execute_btn = QPushButton('执行')
        execute_btn.clicked.connect(self.executeCommand)
        
        cmd_layout.addWidget(QLabel('命令:'))
        cmd_layout.addWidget(self.cmd_input)
        cmd_layout.addWidget(execute_btn)
        
        config_layout.addWidget(cmd_widget)
        
        # 配置文件编辑区域
        edit_area_widget = QWidget()
        edit_area_layout = QHBoxLayout(edit_area_widget)
        
        # 左侧配置文件列表面板
        config_list_widget = QWidget()
        self.config_list_layout = QVBoxLayout(config_list_widget)
        self.config_list_layout.setAlignment(Qt.AlignTop)
        
        # 配置文件列表标题
        self.config_list_layout.addWidget(QLabel('配置文件列表:'))
        
        # 配置文件按钮组
        self.config_file_group = QButtonGroup()
        self.config_file_group.buttonClicked.connect(self.switchConfigFile)
        
        # 默认配置文件列表
        self.config_files = {
            'main': '/etc/nginx/nginx.conf',
            'sites-enabled': '/etc/nginx/sites-enabled/*',
            'conf.d': '/etc/nginx/conf.d/*.conf'
        }
        
        # 添加配置文件按钮
        for name, path in self.config_files.items():
            btn = QPushButton(name)
            btn.setCheckable(True)  # 使按钮可以保持选中状态
            self.config_file_group.addButton(btn)
            self.config_list_layout.addWidget(btn)  # 使用类属性
        
        # 刷新配置列表按钮
        refresh_list_btn = QPushButton('刷新配置列表')
        refresh_list_btn.clicked.connect(self.refreshConfigList)
        self.config_list_layout.addWidget(refresh_list_btn)
        
        # 右侧区域分为左右两部分
        right_area = QWidget()
        right_area_layout = QHBoxLayout(right_area)
        
        # 右侧左半部分（配置编辑）
        edit_widget = QWidget()
        edit_layout = QVBoxLayout(edit_widget)
        
        # 当前文件标签
        self.current_file_label = QLabel('当前文件: 无')
        edit_layout.addWidget(self.current_file_label)
        
        # 配置编辑区
        self.config_text = QTextEdit()
        self.config_text.setReadOnly(True)
        edit_layout.addWidget(self.config_text)
        
        # 编辑控制按钮
        btn_layout = QHBoxLayout()
        self.edit_config_btn = QPushButton('编辑')
        self.save_config_btn = QPushButton('保存')
        self.cancel_config_btn = QPushButton('取消编辑')
        
        self.edit_config_btn.clicked.connect(self.enableConfigEdit)
        self.save_config_btn.clicked.connect(self.saveNginxConfig)
        self.cancel_config_btn.clicked.connect(self.cancelConfigEdit)
        
        self.save_config_btn.setEnabled(False)
        self.cancel_config_btn.setEnabled(False)
        
        btn_layout.addWidget(self.edit_config_btn)
        btn_layout.addWidget(self.save_config_btn)
        btn_layout.addWidget(self.cancel_config_btn)
        edit_layout.addLayout(btn_layout)
        
        # 右侧右半部分（命令输出）
        output_widget = QWidget()
        output_layout = QVBoxLayout(output_widget)
        
        output_layout.addWidget(QLabel('命令输出:'))
        self.cmd_output = QTextEdit()
        self.cmd_output.setReadOnly(True)
        self.cmd_output.setPlaceholderText('命令执行结果将显示在这里...')
        output_layout.addWidget(self.cmd_output)
        
        # 设置右侧两部分的比例
        right_area_layout.addWidget(edit_widget, 2)  # 配置编辑区占2/3
        right_area_layout.addWidget(output_widget, 1)  # 命令输出区占1/3
        
        # 将所有部分组合
        edit_area_layout.addWidget(config_list_widget, 1)  # 左侧列表
        edit_area_layout.addWidget(right_area, 4)  # 右侧区域
        
        config_layout.addWidget(edit_area_widget)
        
        # 添加选项卡
        tab_widget.addTab(control_widget, "控制面板")
        tab_widget.addTab(log_widget, "访问日志")
        tab_widget.addTab(error_log_widget, "错误日志")
        tab_widget.addTab(config_widget, "配置文件")
        
        layout.addWidget(tab_widget)
        
        # 退出按钮
        exit_btn = QPushButton('退出')
        exit_btn.clicked.connect(self.close)
        layout.addWidget(exit_btn)
        
        # 设置定时器更新状态和日志
        self.timer = QTimer()
        self.timer.timeout.connect(self.updateStatus)
        self.timer.start(5000)  # 每5秒更新一次
        
    def loadConfig(self):
        """加载上次成功登录的账户信息"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.ip_input.setText(config.get('ip', ''))
                    self.port_input.setText(config.get('port', '22'))  # 默认端口22
                    self.username_input.setText(config.get('username', 'root'))  # 默认用户名root
                    # 保存加密的密码，供PIN码登录使用
                    self.stored_password = config.get('encrypted_password', '')
        except Exception as e:
            QMessageBox.warning(self, '警告', f'加载配置失败: {str(e)}')

    def saveConfig(self, password_hash):
        """保存账户信息（密码使用不可逆加密）"""
        config = {
            'ip': self.ip_input.text(),
            'port': self.port_input.text(),
            'username': self.username_input.text(),
            'password_hash': password_hash
        }
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f)
        except Exception as e:
            QMessageBox.warning(self, '警告', f'保存配置失败: {str(e)}')

    def connectSSH(self):
        """连接或断开SSH"""
        if self.ssh:  # 如果已经连接，则断开
            try:
                self.ssh.close()
                self.ssh = None
                self.connect_btn.setText('连接')
                self.setInputsEnabled(True)
                self.status_text.setText('已断开连接')
                return
            except Exception as e:
                QMessageBox.critical(self, '错误', f'断开连接失败: {str(e)}')
                return

        # 连接逻辑
        try:
            # 获取输入信息
            ip = self.ip_input.text()
            port = self.port_input.text() or '22'  # 如果端口为空，使用默认值22
            username = self.username_input.text() or 'root'  # 如果用户名为空，使用默认值root
            password = self.password_input.text()
            pin = self.pin_input.text()

            # 验证输入
            if not ip:  # 只检查IP是否为空
                QMessageBox.warning(self, '警告', '请填写IP地址')
                return
            if not (password or pin):
                QMessageBox.warning(self, '警告', '请输入密码或PIN码')
                return

            # PIN码登录逻辑
            if pin:
                if not os.path.exists(self.pin_file):
                    QMessageBox.warning(self, '警告', '未设置PIN码，请使用密码登录')
                    return
                
                # 验证PIN码
                with open(self.pin_file, 'r') as f:
                    stored_pin_hash = f.read()
                if self._hash_value(pin) != stored_pin_hash:
                    QMessageBox.warning(self, '警告', 'PIN码错误')
                    return
                
                # PIN码正确，尝试解密存储的密码
                if not hasattr(self, 'stored_password') or not self.stored_password:
                    QMessageBox.warning(self, '警告', '没有保存的账户信息，请使用密码登录')
                    return
                
                # 使用PIN码解密存储的密码
                decrypted_password = self._decrypt_password(self.stored_password, pin)
                if not decrypted_password:
                    QMessageBox.warning(self, '警告', '密码解密失败，请使用密码重新登录')
                    return
                
                # 使用解密后的密码
                password = decrypted_password

            # 禁用所有输入
            self.setInputsEnabled(False)
            self.connect_btn.setEnabled(True)

            # 创建并启动连接线程
            self.connect_thread = SSHConnectThread(
                ip, port, username, password
            )
            
            # 连接信号
            self.connect_thread.connected.connect(
                lambda success, message: self.onSSHConnected(
                    success, message, 
                    password if not pin else None,  # 如果是PIN码登录，不需要保存新密码
                    pin if not pin else None  # 如果是密码登录且成功，可能需要设置PIN码
                )
            )
            self.connect_thread.status_update.connect(self.status_text.setText)
            
            # 启动线程
            self.connect_thread.start()

        except Exception as e:
            QMessageBox.critical(self, '错误', f'连接失败: {str(e)}')
            self.setInputsEnabled(True)

    def onSSHConnected(self, success, message, password=None, pin=None):
        """SSH连接结果处理"""
        if success:
            self.ssh = self.connect_thread.ssh
            self.status_text.setText(message)  # 直接在状态框显示nginx状态
            self.connect_btn.setText('断开')

            # 如果是密码登录成功，保存加密的密码
            if password:
                # 如果没有PIN码，提示设置
                if not os.path.exists(self.pin_file):
                    reply = QMessageBox.question(
                        self, 
                        '设置PIN码', 
                        '是否要为当前账户设置PIN码？\n设置PIN码后可以使用PIN码快速登录。',
                        QMessageBox.Yes | QMessageBox.No
                    )
                    if reply == QMessageBox.Yes:
                        new_pin = self.setupPIN()
                        if new_pin:
                            # 使用新PIN码加密密码
                            encrypted_password = self._encrypt_password(password, new_pin)
                            # 保存配置
                            config = {
                                'ip': self.ip_input.text(),
                                'port': self.port_input.text(),
                                'username': self.username_input.text(),
                                'encrypted_password': encrypted_password
                            }
                            with open(self.config_file, 'w') as f:
                                json.dump(config, f)
                            QMessageBox.information(self, '成功', 'PIN码设置成功！')
            elif pin:
                # PIN码登录成功后，保存当前会话的密码
                self.current_session_password = self._decrypt_password(self.stored_password, pin)

            # 开始定时更新
            self.updateStatus()
        else:
            self.status_text.setText(f"连接失败: {message}")  # 在状态框显示错误信息
            QMessageBox.critical(self, '错误', message)  # 弹窗显示错误
            self.setInputsEnabled(True)

        # 清理线程
        self.connect_thread.quit()
        self.connect_thread.wait()
        self.connect_thread = None

    def controlNginx(self, action):
        if not self.ssh:
            QMessageBox.warning(self, '警告', '请先连接SSH')
            return
            
        cmd = f'sudo systemctl {action} nginx'
        try:
            stdin, stdout, stderr = self.ssh.exec_command(cmd)
            error = stderr.read().decode()
            if error:
                QMessageBox.warning(self, '警告', f'执行命令失败: {error}')
            else:
                QMessageBox.information(self, '成功', f'Nginx {action} 成功')
                self.updateStatus()
        except Exception as e:
            QMessageBox.critical(self, '错误', f'执行命令失败: {str(e)}')
            
    def updateStatus(self):
        if not self.ssh:
            return
            
        try:
            # 更新Nginx状态
            stdin, stdout, stderr = self.ssh.exec_command('systemctl status nginx')
            self.status_text.setText(stdout.read().decode())
            
            # 更新访问日志
            stdin, stdout, stderr = self.ssh.exec_command('tail -n 50 /var/log/nginx/access.log')
            self.log_text.setText(stdout.read().decode())
            
            # 更新错误日志
            stdin, stdout, stderr = self.ssh.exec_command('tail -n 50 /var/log/nginx/error.log')
            self.error_log_text.setText(stdout.read().decode())
            
            # 更新配置文件（只在首次加载时更新）
            if not hasattr(self, 'config_loaded'):
                stdin, stdout, stderr = self.ssh.exec_command('cat /etc/nginx/nginx.conf')
                self.config_text.setText(stdout.read().decode())
                self.config_loaded = True
                self.original_config = self.config_text.toPlainText()
                
        except Exception as e:
            self.status_text.setText(f'更新状态失败: {str(e)}')
            
    def checkNginxConfig(self):
        if not self.ssh:
            QMessageBox.warning(self, '警告', '请先连接SSH')
            return
            
        try:
            stdin, stdout, stderr = self.ssh.exec_command('nginx -t')
            error = stderr.read().decode()
            QMessageBox.information(self, 'Nginx配置检查', error)
        except Exception as e:
            QMessageBox.critical(self, '错误', f'检查配置失败: {str(e)}')
            
    def closeEvent(self, event):
        if self.ssh:
            self.ssh.close()
        event.accept()

    def enableConfigEdit(self):
        """启用配置文件编辑"""
        self.config_text.setReadOnly(False)
        self.edit_config_btn.setEnabled(False)
        self.save_config_btn.setEnabled(True)
        self.cancel_config_btn.setEnabled(True)
        # 保存当前配置用于取消时恢复
        self.original_config = self.config_text.toPlainText()
        
    def cancelConfigEdit(self):
        """取消配置文件编辑"""
        self.config_text.setReadOnly(True)
        self.edit_config_btn.setEnabled(True)
        self.save_config_btn.setEnabled(False)
        self.cancel_config_btn.setEnabled(False)
        # 恢复原始配置
        self.config_text.setText(self.original_config)
        
    def saveNginxConfig(self):
        """保存文件，对nginx配置文件进行语法检查"""
        if not self.ssh:
            QMessageBox.warning(self, '警告', '请先连接SSH')
            return
            
        try:
            config_content = self.config_text.toPlainText()
            current_file = self.current_file_label.text().replace('当前文件: ', '')
            
            # 判断是否是nginx配置文件
            is_nginx_config = current_file.endswith('.conf') and 'nginx' in current_file
            
            if is_nginx_config:
                # 对nginx配置文件进行语法检查
                sftp = self.ssh.open_sftp()
                with sftp.file('/tmp/nginx.conf.tmp', 'w') as f:
                    f.write(config_content)
                
                stdin, stdout, stderr = self.ssh.exec_command('nginx -t -c /tmp/nginx.conf.tmp')
                error = stderr.read().decode()
                
                if 'test is successful' not in error:
                    QMessageBox.warning(self, '警告', f'Nginx配置文件语法错误:\n{error}')
                    return
                    
                save_msg = 'Nginx配置文件语法检查通过，是否要保存更新？'
            else:
                save_msg = f'是否要保存文件 {current_file}？'
            
            # 询问是否保存
            reply = QMessageBox.question(self, '确认', save_msg, QMessageBox.Yes | QMessageBox.No)
            
            if reply == QMessageBox.Yes:
                try:
                    # 使用临时文件避免权限问题
                    sftp = self.ssh.open_sftp()
                    with sftp.file('/tmp/file.tmp', 'w') as f:
                        f.write(config_content)
                    self.ssh.exec_command(f'sudo cp /tmp/file.tmp "{current_file}"')
                    
                    # 如果是nginx配置文件，提示需要重启
                    if is_nginx_config:
                        QMessageBox.information(self, '成功', 
                            '配置文件已更新。\n注意：可能需要重启Nginx才能使更改生效。')
                    else:
                        QMessageBox.information(self, '成功', '文件保存成功')
                    
                    # 更新成功后禁用编辑
                    self.config_text.setReadOnly(True)
                    self.edit_config_btn.setEnabled(True)
                    self.save_config_btn.setEnabled(False)
                    self.cancel_config_btn.setEnabled(False)
                    
                except Exception as e:
                    QMessageBox.critical(self, '错误', f'保存文件失败: {str(e)}')
                
        except Exception as e:
            QMessageBox.critical(self, '错误', f'操作失败: {str(e)}')

    def switchConfigFile(self, button):
        """切换配置文件"""
        if not self.ssh:
            QMessageBox.warning(self, '警告', '请先连接SSH')
            button.setChecked(False)
            return
            
        try:
            file_name = button.text()
            file_path = self.config_files[file_name]
            
            if '*' in file_path:  # 处理通配符路径
                # 获取目录下的所有配置文件
                base_path = file_path.replace('/*', '').replace('/*.conf', '')
                stdin, stdout, stderr = self.ssh.exec_command(f'ls {base_path}')
                files = stdout.read().decode().strip().split('\n')
                
                if files and files[0]:  # 确保有文件存在
                    # 弹出文件选择对话框
                    file_dialog = QDialog(self)
                    file_dialog.setWindowTitle('选择配置文件')
                    dialog_layout = QVBoxLayout(file_dialog)
                    
                    file_list = QListWidget()
                    file_list.addItems(files)
                    dialog_layout.addWidget(file_list)
                    
                    select_btn = QPushButton('选择')
                    select_btn.clicked.connect(file_dialog.accept)
                    dialog_layout.addWidget(select_btn)
                    
                    if file_dialog.exec_() == QDialog.Accepted and file_list.currentItem():
                        selected_file = file_list.currentItem().text()
                        file_path = f"{base_path}/{selected_file}"
                    else:
                        button.setChecked(False)
                        return
                else:
                    QMessageBox.warning(self, '警告', f'目录 {base_path} 中没有配置文件')
                    button.setChecked(False)
                    return
            
            # 读取选中的配置文件
            stdin, stdout, stderr = self.ssh.exec_command(f'cat {file_path}')
            content = stdout.read().decode()
            error = stderr.read().decode()
            
            if error:
                QMessageBox.warning(self, '警告', f'读取配置文件失败:\n{error}')
                button.setChecked(False)
                return
                
            self.current_file_label.setText(f'当前文件: {file_path}')
            self.config_text.setText(content)
            self.original_config = content
            
        except Exception as e:
            QMessageBox.critical(self, '错误', f'切换配置文件失败: {str(e)}')
            button.setChecked(False)
            
    def refreshConfigList(self):
        """刷新配置文件列表"""
        if not self.ssh:
            QMessageBox.warning(self, '警告', '请先连接SSH')
            return
            
        try:
            # 获取所有配置目录下的文件
            cmd = 'find /etc/nginx -type f -name "*.conf"'
            stdin, stdout, stderr = self.ssh.exec_command(cmd)
            files = stdout.read().decode().strip().split('\n')
            
            # 更新配置文件字典
            self.config_files = {'main': '/etc/nginx/nginx.conf'}
            
            # 清除原有的按钮
            for button in self.config_file_group.buttons():
                self.config_file_group.removeButton(button)
                button.deleteLater()
                
            # 重新添加按钮
            for file_path in files:
                if file_path:
                    name = os.path.basename(file_path)
                    self.config_files[name] = file_path
                    btn = QPushButton(name)
                    btn.setCheckable(True)
                    self.config_file_group.addButton(btn)
                    # 使用类属性添加按钮
                    self.config_list_layout.insertWidget(
                        self.config_list_layout.count() - 1,  # 在最后一个按钮（刷新按钮）之前插入
                        btn
                    )
                    
            QMessageBox.information(self, '成功', '配置文件列表已更新')
            
        except Exception as e:
            QMessageBox.critical(self, '错误', f'刷新配置列表失败: {str(e)}')

    def executeCommand(self):
        """执行用户输入的命令"""
        if not self.ssh:
            QMessageBox.warning(self, '警告', '请先连接SSH')
            return
            
        command = self.cmd_input.text().strip()
        if not command:
            return
            
        # 检查是否是编辑文件的命令
        edit_commands = ['vi', 'vim', 'nano']
        cmd_parts = command.split()
        
        if cmd_parts[0] in edit_commands and len(cmd_parts) > 1:
            # 获取文件路径
            file_path = cmd_parts[-1]
            try:
                # 首先检查文件是否存在
                stdin, stdout, stderr = self.ssh.exec_command(f'test -f {file_path} && echo "exists" || echo "not exists"')
                file_exists = stdout.read().decode().strip() == "exists"
                
                if not file_exists:
                    # 文件不存在，询问是否创建
                    reply = QMessageBox.question(self, '确认', 
                        f'文件 {file_path} 不存在，是否创建？',
                        QMessageBox.Yes | QMessageBox.No)
                    
                    if reply == QMessageBox.Yes:
                        # 创建文件所在的目录（如果不存在）
                        dir_path = os.path.dirname(file_path)
                        if dir_path:
                            self.ssh.exec_command(f'sudo mkdir -p {dir_path}')
                        
                        # 创建空文件
                        self.ssh.exec_command(f'sudo touch {file_path}')
                        # 设置文件权限
                        self.ssh.exec_command(f'sudo chmod 644 {file_path}')
                        content = ""
                    else:
                        return
                else:
                    # 读取现有文件内容
                    stdin, stdout, stderr = self.ssh.exec_command(f'cat {file_path}')
                    content = stdout.read().decode()
                    error = stderr.read().decode()
                    
                    if error:
                        QMessageBox.warning(self, '警告', f'读取文件失败:\n{error}')
                        return
                
                # 更新当前文件标签和内容
                self.current_file_label.setText(f'当前文件: {file_path}')
                self.config_text.setText(content)
                self.original_config = content
                
                # 启用编辑模式
                self.enableConfigEdit()
                
                # 清空命令输入框
                self.cmd_input.clear()
                
            except Exception as e:
                QMessageBox.critical(self, '错误', f'执行命令失败: {str(e)}')
        else:
            try:
                # 执行其他命令
                stdin, stdout, stderr = self.ssh.exec_command(command)
                output = stdout.read().decode()
                error = stderr.read().decode()
                
                # 在命令输出区域显示结果
                result = []
                if output:
                    result.append(f"命令输出:\n{output}")
                if error:
                    result.append(f"错误输出:\n{error}")
                    
                if result:
                    # 更新命令输出显示区域
                    self.cmd_output.setText('\n'.join(result))
                    # 滚动到底部
                    self.cmd_output.verticalScrollBar().setValue(
                        self.cmd_output.verticalScrollBar().maximum()
                    )
                else:
                    self.cmd_output.setText('命令执行成功，无输出')
                
                # 清空命令输入框
                self.cmd_input.clear()
                
            except Exception as e:
                self.cmd_output.setText(f'执行命令失败: {str(e)}')
                QMessageBox.critical(self, '错误', f'执行命令失败: {str(e)}')

    def onPasswordChanged(self, text):
        """密码输入框变化时禁用/启用PIN码输入框"""
        if text:
            self.pin_input.setEnabled(False)
        else:
            self.pin_input.setEnabled(True)

    def onPinChanged(self, text):
        """PIN码输入框变化时禁用/启用密码输入框"""
        if text:
            self.password_input.setEnabled(False)
        else:
            self.password_input.setEnabled(True)

    def setInputsEnabled(self, enabled):
        """设置所有输入框的启用状态"""
        for widget in self.input_widgets:
            widget.setEnabled(enabled)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = SSHManager()
    window.show()
    sys.exit(app.exec_()) 
    window.show()
    sys.exit(app.exec_()) 