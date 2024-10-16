import paramiko
import json
import re
from scp import SCPClient
from prettytable import PrettyTable

import warnings
from cryptography.utils import CryptographyDeprecationWarning

# 忽略 cryptography 的弃用警告
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


class ServerOperations:
    def __init__(self, servers, operation_file='operations.json'):
        self.servers = servers
        self.operation_file = operation_file
        self.custom_operations = self.load_custom_operations()

    def _connect(self, ip, port, username, password):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, port=port, username=username, password=password)
            return ssh
        except Exception as e:
            print(f"Failed to connect to {ip}: {e}")
            return None

    def test_connection(self, server_names):
        """测试与指定服务器的连接"""
        table = PrettyTable()
        table.field_names = ["Server Name", "IP Address", "Status"]

        for name in server_names:
            if name not in self.servers:
                table.add_row([name, self.servers[name]["ip"], "Does not exist"])
                continue

            server_info = self.servers[name]
            ip = server_info["ip"]
            print(f"Testing connection to {name} ({ip})...")
            ssh = self._connect(ip, server_info['port'], server_info['username'], server_info['password'])

            if ssh:
                table.add_row([name, ip, "Connection successful"])
                ssh.close()
            else:
                table.add_row([name, ip, "Connection failed"])

        print("Connection Test Results:")
        print(table)

    def pause(self):
        """Pause the program and wait for user input to continue."""
        input("Press Enter to continue...")

    def execute_command(self, ssh, command):
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        if error:
            print(f"Error executing command: {error}")
        return output

    def distribute_file(self, local_path, remote_path, server_names):
        for name in server_names:
            if name not in self.servers:
                print(f"Server {name} does not exist.")
                continue
            server_info = self.servers[name]
            ssh = self._connect(server_info['ip'], server_info['port'], server_info['username'],
                                server_info['password'])
            if ssh:
                with SCPClient(ssh.get_transport()) as scp:
                    scp.put(local_path, remote_path)
                print(f"File distributed to {name}")
                ssh.close()

    def rename_file(self, old_path, new_path, server_names):
        for name in server_names:
            if name not in self.servers:
                print(f"Server {name} does not exist.")
                continue
            server_info = self.servers[name]
            ssh = self._connect(server_info['ip'], server_info['port'], server_info['username'],
                                server_info['password'])
            if ssh:
                command = f"mv {old_path} {new_path}"
                result = self.execute_command(ssh, command)
                print(f"Renamed file on {name}.{result}")
                ssh.close()

    def move_file(self, src_path, dst_path, server_names):
        for name in server_names:
            if name not in self.servers:
                print(f"Server {name} does not exist.")
                continue
            server_info = self.servers[name]
            ssh = self._connect(server_info['ip'], server_info['port'], server_info['username'],
                                server_info['password'])
            if ssh:
                command = f"mv {src_path} {dst_path}"
                result = self.execute_command(ssh, command)
                print(f"Moved file on {name}.{result}")
                ssh.close()

    def delete_file(self, path, server_names):
        for name in server_names:
            if name not in self.servers:
                print(f"Server {name} does not exist.")
                continue
            server_info = self.servers[name]
            ssh = self._connect(server_info['ip'], server_info['port'], server_info['username'],
                                server_info['password'])
            if ssh:
                command = f"rm -rf {path}"
                result = self.execute_command(ssh, command)
                print(f"Deleted file on {name}.{result}")
                ssh.close()

    def show_io_throughput(self, server_names):
        command = "vmstat 1 2"  # 运行 vmstat，收集 I/O 数据
        output = {}

        for server_name in server_names:
            server_info = self.servers[server_name]
            ip = server_info["ip"]
            ssh = self._connect(ip, server_info['port'], server_info['username'], server_info['password'])
            server_output = self.execute_command(ssh, command)
            output[server_name] = server_output
            ssh.close()

        # 创建 PrettyTable 对象
        table = PrettyTable()
        table.field_names = ["Server", "Block Read (MB)", "Block Write (MB)", "Disk Reads (MB/sec)",
                             "Disk Writes (MB/sec)"]

        for server_name, server_output in output.items():
            io_stats = self.parse_vmstat_output(server_output)
            if io_stats:
                table.add_row([
                    server_name,
                    f"{int(io_stats['block_read']) * 512 / (1024 * 1024):.2f} MB",
                    f"{int(io_stats['block_write']) * 512 / (1024 * 1024):.2f} MB",
                    f"{int(io_stats['disk_reads']) * 512 / (1024 * 1024):.2f} MB/sec",
                    f"{int(io_stats['disk_writes']) * 512 / (1024 * 1024):.2f} MB/sec"
                ])
            else:
                table.add_row([server_name, "N/A", "N/A", "N/A", "N/A"])

        print(table)

    def parse_vmstat_output(self, output):
        """解析 vmstat 输出，提取 I/O 相关信息"""
        lines = output.splitlines()
        if len(lines) > 2:
            stats_line = lines[2].split()
            return {
                "block_read": stats_line[5],  # blocks read
                "block_write": stats_line[6],  # blocks written
                "disk_reads": stats_line[4],  # disk reads per second
                "disk_writes": stats_line[7]  # disk writes per second
            }

        return None

    def show_memory_usage(self, server_names):
        """显示指定服务器的内存使用情况"""
        command = "free -m"  # 获取内存使用情况（以MB为单位）
        output = {}

        # 执行命令获取每个服务器的内存信息
        for server_name in server_names:
            server_info = self.servers[server_name]
            ip = server_info["ip"]
            ssh = self._connect(ip, server_info['port'], server_info['username'], server_info['password'])
            server_output = self.execute_command(ssh, command)
            output[server_name] = server_output
            ssh.close()

        # 初始化表格
        table = PrettyTable()
        table.field_names = ["Server Name", "Total(MB)", "Used(MB)", "Free(MB)",
                             "Buffers/Cache(MB)", "Available(MB)"]

        # 解析并添加数据到表格
        for server_name, server_output in output.items():
            memory_data = self.parse_memory_output(server_output)
            if memory_data:
                table.add_row([
                    server_name,
                    memory_data["total"],
                    memory_data["used"],
                    memory_data["free"],
                    memory_data["buffers_cache"],
                    memory_data["available"]
                ])
            else:
                table.add_row([server_name, "N/A", "N/A", "N/A", "N/A", "N/A"])

        # 打印表格
        print(table)

    def parse_memory_output(self, output):
        """解析 free -m 的输出，返回内存信息"""
        lines = output.splitlines()

        # 确保输出非空
        if not lines or len(lines) < 2:
            return None

        # 查找 'Mem' 行，并解析数据
        for line in lines:
            if line.startswith("Mem:"):
                parts = line.split()
                return {
                    "total": int(parts[1]),  # 总内存
                    "used": int(parts[2]),  # 已使用内存
                    "free": int(parts[3]),  # 空闲内存
                    "buffers_cache": int(parts[5]),  # 缓冲/缓存
                    "available": int(parts[6])  # 可用内存
                }

        return None  # 如果没有找到内存信息则返回 None

    def show_cpu_usage(self, server_names):
        """显示指定服务器节点的 CPU 使用情况"""
        command = "cat /proc/stat"  # 获取 CPU 统计信息
        output = {}
        max_cores_count = 0  # 用于跟踪最大核心数

        for server_name in server_names:
            # 使用 SSH 连接获取每个服务器的输出
            server_info = self.servers[server_name]
            ip = server_info["ip"]
            ssh = self._connect(ip, server_info['port'], server_info['username'], server_info['password'])
            server_output = self.execute_command(ssh, command)
            output[server_name] = server_output
            ssh.close()  # 关闭 SSH 连接

        # 解析所有服务器的 CPU 使用情况，并确定最大核心数
        cpu_usages = {}
        for server_name, server_output in output.items():
            cpu_usage = self.parse_proc_stat_output(server_output)
            cpu_usages[server_name] = cpu_usage

            if cpu_usage:
                max_cores_count = max(max_cores_count, len(cpu_usage['cores']))

        # 确保不超过 8 核心
        max_cores_count = min(max_cores_count, 8)

        # 初始化 PrettyTable
        table = PrettyTable()
        table.field_names = ["Server Name"] + [f"Core {i}" for i in range(max_cores_count)] + [
            "Total CPU Usage"]

        # 遍历服务器名称和其对应的 CPU 使用情况
        for server_name, cpu_usage in cpu_usages.items():
            if cpu_usage:
                core_usage_list = [
                    f"{cpu_usage['cores'].get(f'cpu{i}', 0):.2f}%" for i in range(max_cores_count)
                ]
                total_usage = f"{cpu_usage['total_usage']:.2f}%"

                # 将每个服务器的核心使用情况添加到表格中
                table.add_row([server_name] + core_usage_list + [total_usage])
            else:
                print(f"No CPU usage data available for {server_name}.")

        # 打印表格
        print(table)

    def parse_proc_stat_output(self, output):
        """解析 /proc/stat 输出，返回 CPU 使用情况"""
        lines = output.splitlines()
        if lines:
            cpu_line = lines[0].split()
            total_time = sum(int(x) for x in cpu_line[1:])  # 用户、系统、空闲等时间
            idle_time = int(cpu_line[4])  # 空闲时间
            usage = 100 * (1 - (idle_time / total_time))  # 计算总 CPU 使用率

            # 解析每个核心的使用情况
            cores_usage = {}
            for line in lines[1:]:
                core_info = line.split()

                # 检查是否是有效的核心信息行
                if len(core_info) > 1 and core_info[0].startswith('cpu'):
                    core_id = core_info[0]  # 获取核心 ID
                    core_total_time = sum(int(x) for x in core_info[1:])  # 计算总时间
                    core_idle_time = int(core_info[4])  # 获取空闲时间
                    # 计算核心使用率
                    core_usage = 100 * (1 - (core_idle_time / core_total_time))

                    cores_usage[core_id] = core_usage  # 保存核心使用率

            return {
                "total_usage": usage,
                "cores": cores_usage
            }

        return None

    def show_process_view(self, server_names):
        command = "ps aux"
        output = {}

        for server_name in server_names:
            server_info = self.servers[server_name]
            ip = server_info["ip"]
            ssh = self._connect(ip, server_info['port'], server_info['username'], server_info['password'])
            server_output = self.execute_command(ssh, command)
            output[server_name] = server_output
            ssh.close()

        table = PrettyTable()
        table.field_names = ["Server", "User", "PID", "CPU (%)", "MEM (%)", "Command"]

        for server_name, server_output in output.items():
            lines = server_output.splitlines()[1:]
            for line in lines:
                if line.strip():
                    columns = line.split(None, 10)
                    command_text = columns[10]

                    # 如果命令过长，进行换行
                    if len(command_text) > 50:
                        command_text = "\n".join([command_text[i:i + 50] for i in range(0, len(command_text), 50)])

                    table.add_row([server_name, columns[0], columns[1], columns[2], columns[3], command_text])

        print(table)

    def show_disk_view(self, server_names):
        command = "df -h"
        output = {}

        for server_name in server_names:
            server_info = self.servers[server_name]
            ip = server_info["ip"]
            ssh = self._connect(ip, server_info['port'], server_info['username'], server_info['password'])
            server_output = self.execute_command(ssh, command)
            output[server_name] = server_output
            ssh.close()

        table = PrettyTable()
        table.field_names = ["Server", "Filesystem", "Size", "Used", "Available", "Use%", "Mounted on"]

        # 设置Mounted on列最大宽度
        table.max_width["Mounted on"] = 50

        for server_name, server_output in output.items():
            lines = server_output.splitlines()[1:]  # 跳过标题行
            for line in lines:
                if line.strip():  # 确保行不为空
                    columns = line.split()
                    table.add_row([server_name] + columns)  # 将服务器名与列数据合并

        print(table)

    def show_network_latency(self, server_names, target_ip="8.8.8.8"):
        results = {}
        for server_name in server_names:
            command = f"ping -c 4 {target_ip}"
            server_info = self.servers[server_name]
            ip = server_info["ip"]
            ssh = self._connect(ip, server_info['port'], server_info['username'], server_info['password'])
            output = self.execute_command(ssh, command)
            ssh.close()

            results[server_name] = output

        table = PrettyTable()
        table.field_names = ["Server", "Packet Loss", "Min Latency (ms)", "Avg Latency (ms)", "Max Latency (ms)"]

        for server, output in results.items():
            lines = output.splitlines()
            packet_loss = ""
            min_latency = avg_latency = max_latency = ""

            for line in lines:
                if "loss" in line:
                    packet_loss = line.split(',')[2].strip()
                elif "rtt" in line:
                    latencies = line.split('=')[1].strip().split('/')[0:3]
                    min_latency, avg_latency, max_latency = latencies

            table.add_row([server, packet_loss, min_latency, avg_latency, max_latency])

        print(table)

    def _execute_on_servers(self, server_names, command):
        for name in server_names:
            if name not in self.servers:
                print(f"Server {name} does not exist.")
                continue

            server_info = self.servers[name]
            ip = server_info["ip"]
            print(f"Executing on {name} ({ip})...")
            ssh = self._connect(ip, server_info['port'], server_info['username'], server_info['password'])
            if ssh:
                output = self.execute_command(ssh, command)
                print(f"Output from {name} ({ip}):\n{output}")
                ssh.close()
            else:
                print(f"Failed to connect to {name} ({ip}).")

    def disk_speed_test(self, server_names, test_path="/tmp"):
        results = []

        for name in server_names:
            if name not in self.servers:
                print(f"Server {name} does not exist.")
                continue

            server_info = self.servers[name]
            ip = server_info["ip"]
            print(f"Running disk speed test on {name} ({ip})...")

            ssh = self._connect(ip, server_info['port'], server_info['username'], server_info['password'])
            if ssh:
                # 测试写入速度
                write_test_command = f"dd if=/dev/zero of={test_path}/testfile bs=1G count=1 oflag=direct"
                write_output = self.execute_command(ssh, write_test_command)

                # 测试读取速度
                read_test_command = f"dd if={test_path}/testfile of=/dev/null bs=1G count=1 iflag=direct"
                read_output = self.execute_command(ssh, read_test_command)

                # 删除测试文件
                cleanup_command = f"rm -f {test_path}/testfile"
                self.execute_command(ssh, cleanup_command)

                ssh.close()

                # 解析结果
                write_speed = self.parse_dd_output(write_output)
                read_speed = self.parse_dd_output(read_output)
                results.append((name, write_speed, read_speed))
            else:
                print(f"Failed to connect to {name} ({ip}).")
                results.append((name, "Connection Failed", "Connection Failed"))

        # 使用 PrettyTable 打印结果
        table = PrettyTable()
        table.field_names = ["Server", "Write Speed (MB/s)", "Read Speed (MB/s)"]

        for result in results:
            table.add_row(result)

        print(table)

    def parse_dd_output(self, output):
        """解析 dd 命令输出以提取速度信息"""
        speed = 0.0
        # 正则表达式匹配 dd 的输出
        match = re.search(r'(\d+(?:\.\d+)?)\s+(\w+)\s+copied,\s+(\d+(?:\.\d+)?)\s+s', output)
        if match:
            bytes_copied, unit, duration = match.groups()
            speed = float(bytes_copied) / (1024 * 1024 * float(duration))  # 转换为 MB/s
        return speed

    def execute_os_command(self, server_names, os_command):
        """
        在指定服务器节点或所有节点上执行操作系统命令
        """
        for name in server_names:
            print("*" * 70)
            if name not in self.servers:
                print(f"Server {name} does not exist.")
                continue

            server_info = self.servers[name]
            ip = server_info["ip"]
            print(f"Executing command on {name} ({ip})...")

            ssh = self._connect(ip, server_info['port'], server_info['username'], server_info['password'])
            if ssh:
                # 执行操作系统命令
                output = self.execute_command(ssh, os_command)
                print(f"Command output from {name} ({ip}):\n{'-' * 20}\n{output}")
                ssh.close()
            else:
                print(f"Failed to connect to {name} ({ip}).")

    def load_custom_operations(self):
        """从文件中加载自定义命令"""
        try:
            with open(self.operation_file, 'r') as f:
                custom_commands = json.load(f)
        except FileNotFoundError:
            custom_commands = {}
        return custom_commands

    def save_custom_operations(self):
        """保存自定义命令到文件"""
        with open(self.operation_file, 'w') as f:
            json.dump(self.custom_operations, f, indent=4)

    def create_custom_operation(self):
        """创建一个新的自定义操作"""
        operation_detail = input("Enter the detail of the custom operation: ")
        system_command = input("Enter the system command to execute: ")

        operation_id = str(len(self.custom_operations) + 1)  # 自动分配编号
        self.custom_operations[operation_id] = {
            'detail': operation_detail,
            'command': system_command
        }

        self.save_custom_operations()
        print(f"Custom operation '{operation_detail}' created with ID: {operation_id}")

    def view_custom_operations(self):
        """查看所有自定义操作"""
        if not self.custom_operations:
            print("No custom operation available.")
        else:
            table = PrettyTable()
            table.field_names = ["Operation ID", "Description", "Command"]

            for operation_id, details in self.custom_operations.items():
                table.add_row([operation_id, details['detail'], details['command']])

            print(table)

    def execute_custom_operation(self):
        """在指定服务器上执行自定义操作"""
        # 展示所有自定义命令及其编号
        self.view_custom_operations()

        # 获取用户输入的命令编号
        operation_id = input("Enter the custom operation ID to execute: ")

        # 验证命令编号的有效性
        if operation_id not in self.custom_operations:
            print(f"Operation ID {operation_id} does not exist.")
            return

        # 获取用户输入的服务器名称列表
        server_names = input("Enter server names (comma-separated) or 'all': ").split(',')
        server_names = [name.strip() for name in server_names]  # 去除多余空格
        server_names = ['all'] if server_names == [''] else server_names
        if 'all' in server_names:
            server_names = list(self.servers.keys())
        # 循环遍历服务器名称
        for server_name in server_names:
            # 验证服务器名称的有效性
            if server_name not in self.servers:
                print(f"Server {server_name} does not exist.")
                continue  # 跳过无效服务器，继续下一个

            server_info = self.servers[server_name]
            ip = server_info["ip"]
            command = self.custom_operations[operation_id]['command']

            print(f"Executing operation '{self.custom_operations[operation_id]['detail']}' on {server_name} ({ip})...")

            ssh = self._connect(ip, server_info['port'], server_info['username'], server_info['password'])
            if ssh:
                stdin, stdout, stderr = ssh.exec_command(command)
                output = stdout.read().decode().strip()
                error = stderr.read().decode().strip()

                if error:
                    print(f"Error on {server_name}: {error}")
                else:
                    print(f"Output from {server_name} ({ip}):\n{output}")

                ssh.close()
            else:
                print(f"Failed to connect to {server_name} ({ip}).")

    def delete_custom_operation(self):
        """删除自定义操作"""
        self.view_custom_operations()
        operation_id = input("Enter the custom operation ID to delete: ")

        # 尝试将输入转换为整数
        try:
            int(operation_id)  # 测试能否转换为整数
        except ValueError:
            print("Invalid operation ID format. Please enter a number.")
            return

        if operation_id in self.custom_operations:
            deleted_operation = self.custom_operations.pop(operation_id)
            self.save_custom_operations()
            print(f"Custom operation '{deleted_operation['detail']}' deleted.")

            # 重新分配 ID
            self.reassign_operation_ids()
        else:
            print(f"Operation ID {operation_id} does not exist.")

    def reassign_operation_ids(self):
        """重新分配自定义操作的 ID"""
        new_operations = {}
        for index, (old_id, details) in enumerate(self.custom_operations.items(), start=1):
            new_operations[str(index)] = details  # 从 1 开始重排 ID

        self.custom_operations = new_operations  # 更新操作字典
        self.save_custom_operations()  # 保存重排后的操作

    def view_crontab(self, server_names):
        """查看所有服务器节点或指定服务器节点的定时任务"""
        for name in server_names:
            if name not in self.servers:
                print(f"Server {name} does not exist.")
                continue

            server_info = self.servers[name]
            ssh = self._connect(server_info['ip'], server_info['port'], server_info['username'],
                                server_info['password'])

            if ssh:
                print(f"Current cron jobs on {name}:")
                stdin, stdout, stderr = ssh.exec_command("crontab -l")
                current_crontab = stdout.read().decode().strip().splitlines()

                table = PrettyTable()
                table.field_names = ["Index", "Cron Job"]

                if not current_crontab:
                    print("No cron jobs found.")
                else:
                    for index, line in enumerate(current_crontab):
                        table.add_row([index + 1, line])  # 添加索引和定时任务到表格

                print(table)
                ssh.close()
            else:
                print(f"Failed to connect to {name} ({server_info['ip']}).")

    def create_crontab(self, server_names):
        """在所有服务器节点或指定服务器节点上构建定时任务"""
        cron_expression = input("Enter the cron expression (e.g., '* * * * * /path/to/command'): ").strip()
        command = f'(echo "{cron_expression}" | crontab -)'

        self._execute_on_servers(server_names, command)

    def delete_crontab(self, server_names):
        """在所有服务器节点或指定服务器节点上删除定时任务"""
        # 列出当前的定时任务
        print("Current cron jobs:")
        self.view_crontab(server_names)  # 显示当前定时任务

        # 用户选择要删除的任务索引
        job_index = input("Enter the number of the cron job to delete: ").strip()

        try:
            job_index = int(job_index) - 1  # 转换为索引，从0开始
        except ValueError:
            print("Invalid input. Please enter a number.")
            return

        for name in server_names:
            if name not in self.servers:
                print(f"Server {name} does not exist.")
                continue
            server_info = self.servers[name]
            ssh = self._connect(server_info['ip'], server_info['port'], server_info['username'],
                                server_info['password'])
            if ssh:
                # 获取当前的 crontab
                stdin, stdout, stderr = ssh.exec_command("crontab -l")
                current_crontab = stdout.read().decode().strip().splitlines()

                if 0 <= job_index < len(current_crontab):
                    deleted_job = current_crontab[job_index]
                    # 删除指定的任务
                    new_crontab = [line for i, line in enumerate(current_crontab) if i != job_index]

                    # 更新 crontab
                    if new_crontab:
                        new_crontab_str = "\n".join(new_crontab)
                        update_command = f'echo "{new_crontab_str}" | crontab -'
                    else:
                        update_command = 'crontab -r'  # 如果没有任务了，则删除整个 crontab

                    ssh.exec_command(update_command)
                    print(f"Deleted cron job on {name}: {deleted_job}")
                else:
                    print("Invalid job number. No job deleted.")
                ssh.close()
            else:
                print(f"Failed to connect to {name} ({server_info['ip']}).")

    def run(self):
        while True:
            print("\nChoose an operation:")
            print("1. Test server connections")
            print("2. Distribute file")
            print("3. Rename file")
            print("4. Move file")
            print("5. Delete file")
            print("6. Show CPU usage")
            print("7. Show I/O Throughput")
            print("8. Show Memory Usage")
            print("9. Show Process View")
            print("10. Show Disk View")
            print("11. Show Network Latency")
            print("12. Disk Speed Test")
            print("13. Execute OS Command")
            print("14. View cron jobs")
            print("15. Create cron job")
            print("16. Delete cron job")
            print("0. Back to main menu")

            choice = input(">> ")

            if choice == '1':
                # 新功能：测试连接
                server_names = input("Enter server names (comma-separated) or 'all': ").strip().split(',')
                server_names = ['all'] if server_names == [''] else server_names
                if 'all' in server_names:
                    server_names = list(self.servers.keys())
                self.test_connection(server_names)

            elif choice == '2':
                local_path = input("Enter local file path: ").strip()
                remote_path = input("Enter remote file path: ").strip()
                server_names = input("Enter server names (comma-separated) or 'all': ").strip().split(',')
                server_names = ['all'] if server_names == [''] else server_names
                if 'all' in server_names:
                    server_names = list(self.servers.keys())
                self.distribute_file(local_path, remote_path, server_names)

            elif choice == '3':
                old_path = input("Enter old file path: ").strip()
                new_path = input("Enter new file path: ").strip()
                server_names = input("Enter server names (comma-separated) or 'all': ").strip().split(',')
                server_names = ['all'] if server_names == [''] else server_names
                if 'all' in server_names:
                    server_names = list(self.servers.keys())
                self.rename_file(old_path, new_path, server_names)

            elif choice == '4':
                src_path = input("Enter source file path: ").strip()
                dst_path = input("Enter destination file path: ").strip()
                server_names = input("Enter server names (comma-separated) or 'all': ").strip().split(',')
                server_names = ['all'] if server_names == [''] else server_names
                if 'all' in server_names:
                    server_names = list(self.servers.keys())
                self.move_file(src_path, dst_path, server_names)

            elif choice == '5':
                path = input("Enter file or folder path to delete: ").strip()
                server_names = input("Enter server names (comma-separated) or 'all': ").strip().split(',')
                server_names = ['all'] if server_names == [''] else server_names
                if 'all' in server_names:
                    server_names = list(self.servers.keys())
                self.delete_file(path, server_names)

            elif choice == '6':
                server_names = input("Enter server names (comma-separated) or 'all': ").strip().split(',')
                server_names = ['all'] if server_names == [''] else server_names
                if 'all' in server_names:
                    server_names = list(self.servers.keys())
                self.show_cpu_usage(server_names)

            elif choice == '7':
                server_names = input("Enter server names (comma-separated) or 'all': ").strip().split(',')
                server_names = ['all'] if server_names == [''] else server_names
                if 'all' in server_names:
                    server_names = list(self.servers.keys())
                self.show_io_throughput(server_names)

            elif choice == '8':
                server_names = input("Enter server names (comma-separated) or 'all': ").strip().split(',')
                server_names = ['all'] if server_names == [''] else server_names
                if 'all' in server_names:
                    server_names = list(self.servers.keys())
                self.show_memory_usage(server_names)

            elif choice == '9':
                server_names = input("Enter server names (comma-separated) or 'all': ").strip().split(',')
                server_names = ['all'] if server_names == [''] else server_names
                if 'all' in server_names:
                    server_names = list(self.servers.keys())
                self.show_process_view(server_names)

            elif choice == '10':
                server_names = input("Enter server names (comma-separated) or 'all': ").strip().split(',')
                server_names = ['all'] if server_names == [''] else server_names
                if 'all' in server_names:
                    server_names = list(self.servers.keys())
                self.show_disk_view(server_names)

            elif choice == '11':
                server_names = input("Enter server names (comma-separated) or 'all': ").strip().split(',')
                server_names = ['all'] if server_names == [''] else server_names
                target_ip = input("Enter target IP to ping (default is 8.8.8.8): ") or "8.8.8.8"
                if 'all' in server_names:
                    server_names = list(self.servers.keys())
                self.show_network_latency(server_names, target_ip)

            elif choice == '12':
                server_names = input("Enter server names (comma-separated) or 'all': ").strip().split(',')
                server_names = ['all'] if server_names == [''] else server_names
                test_path = input("Enter path for test file (default is /tmp): ") or "/tmp"
                if 'all' in server_names:
                    server_names = list(self.servers.keys())
                self.disk_speed_test(server_names, test_path)

            elif choice == '13':
                server_names = input("Enter server names (comma-separated) or 'all': ").strip().split(',')
                server_names = ['all'] if server_names == [''] else server_names
                os_command = input("Enter the OS command to execute: ")
                if 'all' in server_names:
                    server_names = list(self.servers.keys())
                self.execute_os_command(server_names, os_command)

            elif choice == '14':
                server_names = input("Enter server names (comma-separated) or 'all': ").strip().split(',')
                server_names = ['all'] if server_names == [''] else server_names
                if 'all' in server_names:
                    server_names = list(self.servers.keys())
                self.view_crontab(server_names)

            elif choice == '15':
                server_names = input("Enter server names (comma-separated) or 'all': ").strip().split(',')
                server_names = ['all'] if server_names == [''] else server_names
                if 'all' in server_names:
                    server_names = list(self.servers.keys())
                self.create_crontab(server_names)

            elif choice == '16':
                server_names = input("Enter server names (comma-separated) or 'all': ").strip().split(',')
                server_names = ['all'] if server_names == [''] else server_names
                if 'all' in server_names:
                    server_names = list(self.servers.keys())
                self.delete_crontab(server_names)

            elif choice == '0':
                break

            else:
                print("Invalid choice")

            self.pause()
