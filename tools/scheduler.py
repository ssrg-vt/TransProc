from pydoc import cli
import paramiko
import os
import sys
import subprocess
import logging

HOST = 1
USER = 2
PASSWD = 3
PORT = 4

ARM_BOARD1 = {
    HOST : "127.0.0.1",
    USER : "root",
    PASSWD : "ubuntu",
    PORT : 5556
}

BOARDS = [ARM_BOARD1]

class SshClient:
    def __init__(self, host, user, passwd, port) -> None:
        self.host = host
        self.user = user
        self.passwd = passwd
        self.port = port
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(host, port, username=user, password=passwd, timeout=10)
    
    def close(self):
        if self.isActive():
            self.client.close()
        logging.info("Connection closed")
    
    def isActive(self) -> bool:
        try:
            if not self.client.get_transport().is_active():
                return False
            self.client.get_transport().send_ignore()
            return True
        except:
            return False
    
    def execute(self, command, sudo=False):
        if sudo:
            command = f"echo {self.passwd} | sudo -S {command}"
        _, stdout, stderr = self.client.exec_command(command)
        errno = stdout.channel.recv_exit_status()
        return stdout, stderr, errno


def initialize_clients(clients):
    logging.info("Initializing clients")
    try:
        for board in BOARDS:
            client = SshClient(board[HOST], board[USER], board[PASSWD], board[PORT])
            clients.append(client)
    except:
        logging.error("Could not initialize ssh clients")
        exit(clients)

def exit(clients):
    for client in clients:
        client.close()
    sys.exit(0)

def main():
    logging.basicConfig(level=logging.INFO)
    clients = []
    initialize_clients(clients)
    for client in clients:
        stdout, stderr, errno = client.execute("ls -al", sudo=True)
        print(f"stdout: {stdout.readlines()}, stderr: {stderr.readline()}, errno: {errno}")
    exit(clients)

if __name__ == "__main__":
    main()