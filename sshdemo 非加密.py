from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                           QTextEdit, QMessageBox, QTabWidget, QDialog, QListWidget,
                           QButtonGroup)
from PyQt5.QtCore import QTimer, Qt, QThread, pyqtSignal
import paramiko
import json
import sys
import os

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
        self.connect_thread = None  # 添加线程属性
        self.initUI()
        self.loadConfig()
        
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
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        
        conn_layout.addWidget(QLabel('IP:'))
        conn_layout.addWidget(self.ip_input)
        conn_layout.addWidget(QLabel('端口:'))
        conn_layout.addWidget(self.port_input)
        conn_layout.addWidget(QLabel('用户名:'))
        conn_layout.addWidget(self.username_input)
        conn_layout.addWidget(QLabel('密码:'))
        conn_layout.addWidget(self.password_input)
        
        # 保存连接按钮的引用
        self.connect_btn = QPushButton('连接')
        self.connect_btn.setObjectName('connect_btn')  # 设置对象名称
        self.connect_btn.clicked.connect(self.connectSSH)
        conn_layout.addWidget(self.connect_btn)
        
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
        
        edit_area_layout.addWidget(config_list_widget, 1)
        
        # 右侧编辑区域
        edit_widget = QWidget()
        edit_layout = QVBoxLayout(edit_widget)
        
        # 当前文件路径显示
        self.current_file_label = QLabel('当前文件: /etc/nginx/nginx.conf')
        edit_layout.addWidget(self.current_file_label)
        
        # 编辑工具栏
        config_btn_layout = QHBoxLayout()
        
        self.edit_config_btn = QPushButton('编辑配置')
        self.edit_config_btn.clicked.connect(self.enableConfigEdit)
        config_btn_layout.addWidget(self.edit_config_btn)
        
        self.save_config_btn = QPushButton('保存配置')
        self.save_config_btn.clicked.connect(self.saveNginxConfig)
        self.save_config_btn.setEnabled(False)
        config_btn_layout.addWidget(self.save_config_btn)
        
        self.cancel_config_btn = QPushButton('取消编辑')
        self.cancel_config_btn.clicked.connect(self.cancelConfigEdit)
        self.cancel_config_btn.setEnabled(False)
        config_btn_layout.addWidget(self.cancel_config_btn)
        
        edit_layout.addLayout(config_btn_layout)
        
        # 配置文本编辑框
        self.config_text = QTextEdit()
        self.config_text.setReadOnly(True)
        edit_layout.addWidget(self.config_text)
        
        edit_area_layout.addWidget(edit_widget, 4)
        
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
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.ip_input.setText(config.get('ip', ''))
                    self.port_input.setText(config.get('port', ''))
                    self.username_input.setText(config.get('username', ''))
                    self.password_input.setText(config.get('password', ''))
        except Exception as e:
            QMessageBox.warning(self, '警告', f'加载配置失败: {str(e)}')
            
    def saveConfig(self):
        config = {
            'ip': self.ip_input.text(),
            'port': self.port_input.text(),
            'username': self.username_input.text(),
            'password': self.password_input.text()
        }
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f)
        except Exception as e:
            QMessageBox.warning(self, '警告', f'保存配置失败: {str(e)}')
            
    def connectSSH(self):
        """连接到SSH服务器"""
        # 禁用连接按钮，避免重复点击
        self.sender().setEnabled(False)
        
        # 如果存在旧连接，先关闭
        if self.ssh:
            self.ssh.close()
            self.ssh = None
        
        # 创建并启动连接线程
        self.connect_thread = SSHConnectThread(
            self.ip_input.text(),
            self.port_input.text(),
            self.username_input.text(),
            self.password_input.text()
        )
        
        # 连接信号
        self.connect_thread.connected.connect(self.onSSHConnected)
        self.connect_thread.status_update.connect(self.status_text.setText)
        
        # 启动线程
        self.connect_thread.start()

    def onSSHConnected(self, success, message):
        """SSH连接结果处理"""
        # 重新启用连接按钮
        self.connect_btn.setEnabled(True)  # 使用保存的按钮引用
        
        if success:
            self.ssh = self.connect_thread.ssh
            self.status_text.setText(message)
            self.saveConfig()
            QMessageBox.information(self, '成功', 'SSH连接成功！')
            # 开始定时更新
            self.updateStatus()
        else:
            self.status_text.setText(message)
            QMessageBox.critical(self, '错误', message)
        
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
                
                if output or error:
                    # 显示命令输出
                    result = f"命令输出:\n{output}\n错误输出:\n{error}"
                    QMessageBox.information(self, '命令执行结果', result)
                
                # 清空命令输入框
                self.cmd_input.clear()
                
            except Exception as e:
                QMessageBox.critical(self, '错误', f'执行命令失败: {str(e)}')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = SSHManager()
    window.show()
    sys.exit(app.exec_()) 