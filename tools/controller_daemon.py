import subprocess
import os
import sys
import time

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


def assert_conditions(dir, bin, tranproc):
    assert os.path.exists(os.path.join(dir, bin))
    assert os.path.exists(os.path.join(dir, "Makefile"))
    bin_dir = os.path.join(dir, "bin/")
    assert os.path.exists(bin_dir)
    assert os.path.exists(os.path.join(bin_dir, bin+"_aarch64"))
    assert os.path.exists(os.path.join(bin_dir, bin+"_x86-64"))
    debugger = os.path.join(tranproc, "tools", "debugger")
    assert os.path.exists(debugger)


addr = "0x50146f"
dir = "/home/abhishek/temp/snu_npb/bt/temp/"
bin = "bt"
tranproc = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

assert_conditions(dir, bin, tranproc)
cd = ControllerDaemon()
# cd.run(os.path.join(dir, bin), dir)
cd.run_and_infect(addr, bin, dir)
time.sleep(1)
pid = cd.get_pid(bin)
print("PID: %s", pid)
#cd.dump(pid, dir)
print('Parent process ends')