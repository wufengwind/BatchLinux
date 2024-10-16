import json
import os
from operations import ServerOperations
from prettytable import PrettyTable

# 服务器节点持久化存储文件路径
SERVER_FILE = 'servers.json'


def load_servers():
    if not os.path.exists(SERVER_FILE):
        return {}
    with open(SERVER_FILE, 'r') as f:
        return json.load(f)


def save_servers(servers):
    with open(SERVER_FILE, 'w') as f:
        json.dump(servers, f, indent=4)


def add_server(servers):
    name = input("Enter server name: ").strip()
    if name in servers:
        print(f"Server {name} already exists!")
        return
    ip = input("Enter server IP: ").strip()
    port = input("Enter ssh port: ").strip()
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()
    servers[name] = {"name": name, "ip": ip, "port": port, "username": username, "password": password}
    save_servers(servers)
    print(f"Server {name} added.")


def delete_server(servers):
    name = input("Enter server name to delete: ")
    if name in servers:
        del servers[name]
        save_servers(servers)
        print(f"Server {name} deleted.")
    else:
        print(f"Server {name} not found.")


def list_servers(servers):
    """列出所有服务器信息"""
    table = PrettyTable()
    table.field_names = ["Server Name", "IP", "Port", "Username", "Password"]

    for name, info in servers.items():
        table.add_row([name, info['ip'], info['port'], info['username'], info['password']])

    print(table)


def manage_operation_lists(ops):
    """管理自定义操作清单"""
    # ops = ServerOperations(servers)

    while True:
        print("\nManage Custom Operation Lists:")
        print("1. Create a Operation List")
        print("2. View Operation Lists")
        print("3. Execute a Operation List")
        print("4. Delete a Operation List")
        print("0. Back to main menu")

        choice = input(">> ")

        if choice == '1':
            ops.create_custom_operation()
        elif choice == '2':
            ops.view_custom_operations()
        elif choice == '3':
            ops.execute_custom_operation()
        elif choice == '4':
            ops.delete_custom_operation()
        elif choice == '0':
            break
        else:
            print("Invalid choice")

        ops.pause()


def main():
    servers = load_servers()
    ops = ServerOperations(servers)
    while True:
        print("\nChoose an action:")
        print("1. Add server")
        print("2. Delete server")
        print("3. List servers")
        print("4. Perform operations on servers")
        print("5. Manage custom operation lists")
        print("0. Exit")

        choice = input("> ")

        if choice == '1':
            add_server(servers)
        elif choice == '2':
            delete_server(servers)
        elif choice == '3':
            list_servers(servers)
        elif choice == '4':
            ops.run()
        elif choice == '5':
            manage_operation_lists(ops)
        elif choice == '0':
            break
        else:
            print("Invalid choice")
        ops.pause()


if __name__ == '__main__':
    main()
