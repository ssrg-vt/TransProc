import paramiko
import os
import subprocess
import logging
import threading
import time
import psutil
import glob

from scp import SCPClient

RUN_DURATION = 60 #seconds
IDEAL_RUN_DURATION = 3600 #seconds

THREAD_PER_BOARD = 3
LOCAL_THREAD_COUNT = 7

HOST = 1
USER = 2
PASSWD = 3
PORT = 4
TPATH = 5

BT = "bt"
CG = "cg"
EP = "ep"
MG = "mg"

ARM_BOARD1 = {
    HOST : "10.1.1.222",
    USER : "abhishek",
    PASSWD : "abhishek",
    PORT : 22,
    TPATH: "/home/abhishek/TransProc"
}

BOARDS = [ARM_BOARD1]

ADDRESSES = {
    BT : "0x501242",
    CG : "0x501052",
    EP : "0x501557",
    MG : "0x50155d"
}

LOCAL_PASSWD = ""

class SshClient:
    def __init__(self, host, user, passwd, port):
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
    def __init__(self, jobSet, threadId):
        threading.Thread.__init__(self)
        self.jobSetIdx = threadId
        self.jobSet = jobSet
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
        
    def getThroughput(self):
        return (self.counter/self.actualRunDuration)*IDEAL_RUN_DURATION


    def _runJobSet(self):
        self.jobSetIdx %= len(self.jobSet)
        subprocess.run(self.jobSet[self.jobSetIdx],
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.STDOUT)
        self.jobSetIdx += 1
            

JOBSET1 = ["/home/abhishek/bt/bt"]
JOBSET2 = []
JOBSET3 = []

JOBSET = {
    0: [JOBSET1, 0],
    1: [JOBSET2, 0] ,
    2: [JOBSET3, 0],
}

class RemoteThread (threading.Thread):
    #runs 1 SSH connection per thread
    #runs on a shared global remote job set
    #1. SCP the job set on the destination node from src node
    #2. run an SSH command to run the job remotely
    #3. Similar logic implemented in local thread to keep track of all the job run
    def __init__(self, jobSetID, lock, host, user, passwd, port):
        threading.Thread.__init__(self)
        self.client = SshClient(host, user, passwd, port)
        self.jobSetId = jobSetID
        self.lock = lock
        self.rootDir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.criu = os.path.join(self.rootDir, "criu-3.15", "criu", "criu")
        self.crit = os.path.join(self.rootDir, "criu-3.15", "crit", "crit")
        self.actualRunDuration = 0
        self.counter = 0
    
    def _getJobPath(self):
        with self.lock:
            job = JOBSET[self.jobSetId][0][JOBSET[self.jobSetId][1]]
            JOBSET[self.jobSetId][1] = 1
            JOBSET[self.jobSetId][1] %= len(JOBSET[self.jobSetId][0])
        return job
    
    def _deleteFiles(self, cwd):
        fileList = glob.glob(os.path.join(cwd, "*.img"), recursive=False)
        for file in fileList:
            deleteCommand = ["rm", file]
            self._spawn_dependent_subprocess(deleteCommand, cwd=cwd, sudo=True, passwd=LOCAL_PASSWD)
    
    def _run(self):
        jobPath = self._getJobPath() #"/home/abhishek/bt/bt"
        aarch64Dir = os.path.join(os.path.dirname(jobPath), "aarch64")
        srcDir = os.path.dirname(jobPath)
        destDir = "/tmp/null/" #os.path.dirname(jobPath)
        fn = os.path.basename(jobPath)
        #checkpoint
        self._dump(fn, srcDir, ADDRESSES[fn])
        #recode
        recodeCommand = f"{self.crit} recode {srcDir} {aarch64Dir} aarch64 {fn} bin n".split()
        self._spawn_dependent_subprocess(recodeCommand, cwd=srcDir, sudo=True, passwd=LOCAL_PASSWD)
        # #scp
        self.client.scp_dir_contents(aarch64Dir, destDir)

        self._deleteFiles(srcDir)
        #restore
        restoreCommand = f"ssh -t {self.client.user}@{self.client.host}".split()
        restoreCommand.append(f"cd {srcDir} ; sudo {self.criu} restore -vv -o restore.log --shell-job")
        subprocess.run(restoreCommand, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        
    
    def _spawn_independent_subprocess(self, args, cwd=None):
        try:
            pid = os.fork()
            if pid > 0:
                #parent process, return and continue execution.
                os.waitpid(pid, 0)
                return
        except OSError as e:
            print("fork failed: %d, (%s)" % e.errno, e.strerror)
            return
        
        try:
            pid2 = os.fork()
            if pid2 > 0:
                #exit from here to continue daemon's execution. 
                #pid of the child will be waited on by init process.
                os._exit(0)
        except OSError as e:
            print("fork 2 failed: %d, (%S)" % e.errno, e.strerror)
        
        # spawn the subprocess, wait on it, then exit.
        proc = subprocess.Popen(args,
                            cwd=cwd,
                            universal_newlines=True,
                            preexec_fn=os.setpgrp)
        proc.wait()
        os._exit(0)
    
    def _spawn_dependent_subprocess(self, args, cwd=None, sudo=False, passwd=""):
        if sudo:
            args = ["sudo",  "-S"] + args
        proc = subprocess.Popen(args, cwd=cwd, 
                            universal_newlines=True,
                            stdin=subprocess.PIPE)
        if sudo:
            proc.communicate(passwd + "\n")
        ret_code = proc.wait()
        return ret_code
    
    def _check_pid(self, bin):
        pid = [p.pid for p in psutil.process_iter() if p.name() == bin]
        if pid: 
            return pid[0]
        return None
    
    def _run_and_infect(self, addr, bin, cwd):
        debugger = os.path.join(self.rootDir, "tools", "debugger")
        self._spawn_independent_subprocess([debugger, bin, addr], cwd=cwd)
    
    def _dump(self, bin, cwd, addr):
        pid = None
        while pid is None:
            self._run_and_infect(addr, bin, cwd)
            pid = self._check_pid(bin)
        command = f"{self.criu} dump -vv -o dump.log -t {pid} --shell-job".split()
        self._spawn_dependent_subprocess(command, cwd=cwd, sudo=True, passwd=LOCAL_PASSWD)
    
    def run(self):
        self.counter = 0
        start = time.perf_counter()
        while True:
            stdout, stderr, errno = self._run()
            if errno != 0:
                logging.error(f"Host: {self.client.host} Errno: {errno} Error while restoring remotely")
            self.counter += 1
            diff = time.perf_counter() - start
            if diff > RUN_DURATION:
                self.actualRunDuration = diff
                break


# def initialize_clients(clients):
#     logging.info("Initializing clients")
#     try:
#         for board in BOARDS:
#             client = SshClient(board[HOST], board[USER], board[PASSWD], board[PORT])
#             clients.append(client)
#     except:
#         logging.error("Could not initialize ssh clients")
#         exit(clients)

# def exit(clients):
#     for client in clients:
#         client.close()
#     sys.exit(0)

LOCALJOBSET = [
    "/home/abhishek/dapper_throughput_efficiency_x86-64/bt_x86-64",
    "/home/abhishek/dapper_throughput_efficiency_x86-64/cg_x86-64",
    "/home/abhishek/dapper_throughput_efficiency_x86-64/ep_x86-64",
    "/home/abhishek/dapper_throughput_efficiency_x86-64/mg_x86-64"
]

def main():
    logging.basicConfig(level=logging.INFO)
    # localThreads = []
    # for i in range(LOCAL_THREAD_COUNT):
    #     localThreads.append(LocalThread(LOCALJOBSET, i))
    #     localThreads[-1].start()
    
    # for localThread in localThreads:
    #     localThread.join()

    for board in BOARDS:
        try:
            rThread = RemoteThread(0, threading.Lock(), board[HOST], board[USER], board[PASSWD], board[PORT])
            rThread.start()
            rThread.join()
            rThread.client.close()
        except Exception as e:
            logging.error(e, "Error while working on remote thread")

if __name__ == "__main__":
    main()