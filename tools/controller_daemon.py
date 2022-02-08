import subprocess
import os

class ControllerDaemon:
    def __init__(self, dir, bin, tranproc, print_stdout = True) -> None:
        self.dir = dir
        self.bin = bin
        self.print_stdout = print_stdout
        self.tranproc = tranproc


    def assert_conditions(self):
        assert os.path.exists(os.path.join(self.dir, self.bin))
        assert os.path.exists(os.path.join(self.dir, "Makefile"))
        bin_dir = os.path.join(self.dir, "bin/")
        assert os.path.exists(bin_dir)
        assert os.path.exists(os.path.join(bin_dir, self.bin+"_aarch64"))
        assert os.path.exists(os.path.join(bin_dir, self.bin+"_x86-64"))
        debugger = os.path.join(self.tranproc, "tools", "debugger")
        assert os.path.exists(debugger)


    def run(self):
        proc = subprocess.Popen(os.path.join(self.dir, self.bin),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            cwd=self.dir,
                            universal_newlines=True)
        stdout, stderr = proc.communicate()
        if self.print_stdout:
            print(stdout)


    def run_and_infect(self, addr):
        debugger = os.path.join(self.tranproc, "tools", "debugger")
        proc = subprocess.Popen([debugger, self.bin, addr],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            cwd=self.dir,
                            universal_newlines=True)
    

    def get_pid(self):
        ps = subprocess.Popen(["ps", "-a"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            universal_newlines=True)
        stdo, stder = ps.communicate()
        o = stdo.splitlines()
        bin = [b for b in o if self.bin in b]
        pid = bin[0].split(' ')
        return pid[2]
    

    def dump(self, pid):
        proc = subprocess.Popen(["make", "PID=%s" % pid, "dump"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            cwd=self.dir,
                            universal_newlines=True)


addr = "0x50146f"
cd = ControllerDaemon("/home/abhishek/temp/snu_npb/bt/temp/", "bt", "/home/abhishek/projects/TranProc/")
cd.assert_conditions()
cd.run_and_infect(addr)
pid = cd.get_pid()
cd.dump(pid)
print('dumped')