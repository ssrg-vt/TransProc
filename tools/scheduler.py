from multiprocessing.pool import RUN
import paramiko
import os
import sys
import subprocess
import logging
import threading
import time

from scp import SCPClient

RUN_DURATION = 600 #seconds
IDEAL_RUN_DURATION = 3600 #seconds

THREAD_PER_BOARD = 3

HOST = 1
USER = 2
PASSWD = 3
PORT = 4

BT = 0
CG = 1
EP = 2
MG = 3

ARM_BOARD1 = {
    HOST : "127.0.0.1",
    USER : "root",
    PASSWD : "ubuntu",
    PORT : 5556
}

BOARDS = [ARM_BOARD1]

ADDRESSES = {
    BT : "0x501242",
    CG : "0x501052",
    EP : "0x501557",
    MG : "0x50155d"
}

class SshClient:
    def __init__(self, host, user, passwd, port) -> None:
        self.host = host
        self.user = user
        self.passwd = passwd
        self.port = port
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(host, port, username=user, password=passwd, timeout=10)
        self.scp = SCPClient(self.client.get_transport())
    
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
    
    def scp_file(self, src_file_path, dest_file_path):
        self.scp.put(src_file_path, dest_file_path)

    def scp_dir_contents(self, src_dir, dest_dir):
        self.scp.put(src_dir, recursive=True, remote_path=dest_dir)


class LocalThread (threading.Thread):
    #Constantly keep running the job provided and measure thread throughput
    def __init__(self, jobPath):
        threading.Thread.__init__(self)
        self.jobPath = jobPath
        self.actualRunDuration = 0
        self.counter = 0

    def run(self):
        self.counter = 0
        start = time.perf_counter()
        while True:
            self._runJobSet()
            self.counter += 1
            diff = time.perf_counter() - start
            if diff > RUN_DURATION:
                self.actualRunDuration = diff
                break

    def _runJobSet(self):
        subprocess.run(self.jobPath,
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.STDOUT)


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
        client.scp_dir_contents("/home/abhishek/bt/aarch64/", "/home/abhishek/bt/")
    exit(clients)

if __name__ == "__main__":
    main()