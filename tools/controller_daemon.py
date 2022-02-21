import subprocess
import os
import sys
import time
import Pyro4
import platform
import psutil


DELAY_PRECISION = 0.01


NAME_PREFIX = "stack_pop.controller_daemon."
CPU_ARCH = platform.processor()
SERVER_NAME = NAME_PREFIX + CPU_ARCH


@Pyro4.expose
@Pyro4.behavior(instance_mode="single")
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
            return
        
        # execution from here is only continued by the child process
        # spawn the subprocess and exit
        proc = subprocess.Popen(args,
                            cwd=cwd,
                            universal_newlines=True,
                            preexec_fn=os.setpgrp)
        sys.exit(0)


    def _spawn_dependent_subprocess(self, args, cwd=None):
        proc = subprocess.Popen(args, cwd=cwd, universal_newlines=True)


    """
    - Do not use with Pyro. As serializing functions is not possible.
    - Keeping it here for some possible future use.
    """
    def _busy_wait(self, f=None):
        assert f, "No function provided to wait on"
        i = 1
        item = None
        while True:
            item = f()
            if item:
                break
            if i > 10:
                break
            time.sleep(i*DELAY_PRECISION)
            i += 1
        return item
    

    def check_errors(self, cwd, bin):
        errors = []
        error = False
        if not os.path.exists(os.path.join(cwd, bin)):
            error |= True
            errors.append("Binary %s does not exist in working directory" % bin)
        if not os.path.exists(os.path.join(cwd, "Makefile")):
            error |= True
            errors.append("Makefile does not exist in working directory")
        bin_dir = os.path.join(cwd, "bin/")
        if not os.path.exists(bin_dir):
            error |= True
            errors.append("bin directory does not exist in working directory")
        if not os.path.exists(os.path.join(bin_dir, bin+"_aarch64")):
            error |= True
            errors.append("Binary %s does not exist in bin directory" % bin+"_aarch64")
        if not os.path.exists(os.path.join(bin_dir, bin+"_x86-64")):
            error |= True
            errors.append("Binary %s does not exist in bin directory" % bin+"_x86-64")
        debugger = os.path.join(self.root_dir, "tools", "debugger")
        if not os.path.exists(debugger):
            error |= True
            errors.append("debugger does not exist in project directory")
        attach_pid = os.path.join(self.root_dir, "tools", "attach_pid")
        if not os.path.exists(attach_pid):
            error |= True
            errors.append("attach_pid does not exist in working directory")
        return (error, errors)


    def run(self, command, cwd):
        self._spawn_independent_subprocess(command, cwd=cwd)


    def run_and_infect(self, addr, bin, cwd):
        debugger = os.path.join(self.root_dir, "tools", "debugger")
        self._spawn_independent_subprocess([debugger, bin, addr], cwd=cwd)
    

    def check_pid(self, bin):
        i = 1
        while True:
            pid = [p.pid for p in psutil.process_iter() if p.name() == bin]
            if pid: 
                return str(pid[0])
            else:
                if i > 10:
                    return None
                time.sleep(i*DELAY_PRECISION)
                i += 1
    

    def check_killed(self, bin):
        i = 1
        while True:
            pid = [p.pid for p in psutil.process_iter() if p.name() == bin]
            if pid:
                if i > 10:
                    return None
                time.sleep(i*DELAY_PRECISION)
                i += 1
            else:
                return "killed"


    def dump(self, pid, cwd):
        proc = psutil.Process(int(pid))
        i = 1
        while True:
            if proc.status() != psutil.STATUS_STOPPED:
                time.sleep(i*DELAY_PRECISION)
                i += 10
            else:
                break
        self._spawn_dependent_subprocess(["make", "PID=%s" % pid, "dump"], cwd=cwd)
    

    def transform(self, bin, tgt, dir, debug='n'):
        bin_dir = os.path.join(dir, "bin/")    
        self._spawn_dependent_subprocess(
            [
             "make", 
             "BIN=%s" % bin, 
             "BINDIR=%s" % bin_dir, 
             "TGT=%s" % tgt, 
             "DEBUG=%s" % debug, 
             "transform"
            ], cwd=dir)
    

    def restore(self, bin, cwd):
        self._spawn_independent_subprocess(["make", "BIN=%s" % bin, "restore"], cwd=cwd)
        pid = self.check_pid(bin)
        self.sigcont(pid)
    

    def restore_and_infect(self, bin, cwd, pid, addr):
        attach_pid = os.path.join(self.root_dir, "tools", "attach_pid")
        self._spawn_independent_subprocess(["make", "BIN=%s" % bin, "restore"], cwd=cwd)
        pid2 = self.check_pid(bin)
        self._spawn_independent_subprocess([attach_pid, pid, addr], cwd=cwd)


    def sigcont(self, pid):
        self._spawn_independent_subprocess(["kill", "-SIGCONT", "%s" % pid])


def main():
    Pyro4.Daemon.serveSimple(
        {
            ControllerDaemon: SERVER_NAME
        },
        ns=True
    )


if __name__ == "__main__":
    main()


# addr = "0x50146f"
# addr2 = "0x50193f"
# dir = "/root/bt"
# bin = "bt"
# tranproc = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# # assert_conditions(dir, bin, tranproc)
# cd = ControllerDaemon()
# # cd.run(os.path.join(dir, bin), dir)
# cd.run_and_infect(addr, bin, dir)
# pid = cd.check_pid(bin)
# cd.dump(pid, dir)
# cd.check_killed(bin)
# cd.transform(bin, "aarch64", dir)
# # cd.restore(bin, dir, pid)
# cd.restore_and_infect(bin, dir, pid, addr2)

# print('Parent process ends')