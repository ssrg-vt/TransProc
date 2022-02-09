from curses.ascii import DEL
import subprocess
import os
import sys
import time


DELAY = 0.1 #TODO: find out a better way.


class ControllerDaemon:
    def __init__(self):
        self.root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    
    def _spawn_independent_subprocess(self, args, cwd=None):
        try:
            pid = os.fork()
            if pid > 0:
                #parent process, return and continue execution.
                return
        except OSError as e:
            print("fork failed: %d, (%s)" % e.errno, e.strerror)
        
        # execution from here is only continued by the child process
        # spawn the subprocess and exit
        proc = subprocess.Popen(args,
                            cwd=cwd,
                            universal_newlines=True,
                            preexec_fn=os.setpgrp)
        sys.exit(0)


    def run(self, command, cwd):
        self._spawn_independent_subprocess(command, cwd=cwd)


    def run_and_infect(self, addr, bin, cwd):
        debugger = os.path.join(self.root_dir, "tools", "debugger")
        self._spawn_independent_subprocess([debugger, bin, addr], cwd=cwd)
    

    def get_pid(self, bin):
        return subprocess.check_output(["pidof", bin], universal_newlines=True)
    

    def dump(self, pid, cwd):
        self._spawn_independent_subprocess(["make", "PID=%s" % pid, "dump"], cwd=cwd)
    

    def transform(self, bin, tgt, dir, debug='n'):
        bin_dir = os.path.join(dir, "bin/")    
        self._spawn_independent_subprocess(
            [
             "make", 
             "BIN=%s" % bin, 
             "BINDIR=%s" % bin_dir, 
             "TGT=%s" % tgt, 
             "DEBUG=%s" % debug, 
             "transform"
            ], cwd=dir)
    

    def restore(self, bin, cwd, pid):
        self._spawn_independent_subprocess(["make", "BIN=%s" % bin, "restore"], cwd=cwd)
        time.sleep(DELAY)
        self._spawn_independent_subprocess(["kill", "-SIGCONT", pid])
    

    def restore_and_infect(self, bin, cwd, pid, addr):
        attach_pid = os.path.join(self.root_dir, "tools", "attach_pid")
        self.restore(bin, cwd, pid)
        self._spawn_independent_subprocess([attach_pid, pid, addr], cwd=cwd)


def assert_conditions(dir, bin, tranproc):
    assert os.path.exists(os.path.join(dir, bin))
    assert os.path.exists(os.path.join(dir, "Makefile"))
    bin_dir = os.path.join(dir, "bin/")
    assert os.path.exists(bin_dir)
    assert os.path.exists(os.path.join(bin_dir, bin+"_aarch64"))
    assert os.path.exists(os.path.join(bin_dir, bin+"_x86-64"))
    debugger = os.path.join(tranproc, "tools", "debugger")
    assert os.path.exists(debugger)
    attach_pid = os.path.join(tranproc, "tools", "attach_pid")
    assert os.path.exists(attach_pid)


addr = "0x50146f"
addr2 = "0x501052"
dir = "/root/bt"
bin = "bt"
tranproc = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

assert_conditions(dir, bin, tranproc)
cd = ControllerDaemon()
# cd.run(os.path.join(dir, bin), dir)
cd.run_and_infect(addr, bin, dir)
time.sleep(DELAY)
pid = cd.get_pid(bin)
cd.dump(pid, dir)
time.sleep(DELAY)
cd.transform(bin, "aarch64", dir)
cd.restore_and_infect(bin, dir, pid, addr2)

print('Parent process ends')