from curses.ascii import DEL
import subprocess
import os
import sys
import time


DELAY = 0.1 #TODO: find out a better way.
DELAY_PRECISION = 0.01


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


    def _busy_wait(self, f=None):
        assert f, "No function provided to wait on"
        i = 1
        item = None
        while True:
            item = f()
            print(item)
            if item:
                break
            if i > 10:
                break
            time.sleep(i*DELAY_PRECISION)
            i += 1
        return item


    def run(self, command, cwd):
        self._spawn_independent_subprocess(command, cwd=cwd)


    def run_and_infect(self, addr, bin, cwd):
        debugger = os.path.join(self.root_dir, "tools", "debugger")
        self._spawn_independent_subprocess([debugger, bin, addr], cwd=cwd)
    

    def check_pid(self, bin):
        def f():
            try:
                pid = subprocess.check_output(["pidof", bin], universal_newlines=True).strip()
                return pid
            except:
                return None
        pid = self._busy_wait(f)
        return pid
    

    def check_killed(self, bin):
        def f():
            try:
                pid = subprocess.check_output(["pidof", bin], universal_newlines=True).strip()
                return None
            except:
                return "Killed"
        state = self._busy_wait(f)


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
    

    def restore_and_infect(self, bin, cwd, pid, addr):
        attach_pid = os.path.join(self.root_dir, "tools", "attach_pid")
        self.restore(bin, cwd, pid)
        self._spawn_independent_subprocess([attach_pid, pid, addr], cwd=cwd)


    def sigcont(self, pid):
        self._spawn_independent_subprocess(["kill", "-SIGCONT", "%s" % pid])


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
addr2 = "0x50193f"
dir = "/root/bt"
bin = "bt"
tranproc = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# assert_conditions(dir, bin, tranproc)
cd = ControllerDaemon()
# cd.run(os.path.join(dir, bin), dir)
cd.run_and_infect(addr, bin, dir)
# time.sleep(DELAY)
pid = cd.check_pid(bin)
cd.dump(pid, dir)
cd.check_killed(bin)
cd.transform(bin, "aarch64", dir)
# cd.restore(bin, dir, pid)
cd.restore_and_infect(bin, dir, pid, addr2)

print('Parent process ends')