from audioop import add
from distutils.debug import DEBUG
import json
import sys
import getopt
import os
import Pyro4
import Pyro4.util
import Pyro4.errors
import time

X86_64 = "x86-64"
AARCH64 = "aarch64"

CONFIG_FILE_NAME = "config.json"

X86_64_SERVER_NAME = "stack_pop.controller_daemon.x86_64"
AARCH64_SERVER_NAME = "stack_pop.controller_daemon.aarch64"

DELAY_PRECISION = 0.01

"""
Instruct Modes:
"""
RUN = "run"
RUN_AND_INFECT = "run_and_infect"
DUMP = "dump"
TRANSFORM = "transform"
RESTORE = "restore"
RESTORE_AND_INFECT = "restore_and_infect"


def verbose(func_name, msg):
    if VERBOSE:
        print(func_name + ": " + msg)


def check_pid(server, bin):
    i = 1
    while True:
        try:
            pid = server.check_pid(bin)
            verbose(sys._getframe().f_code.co_name, "PID is %s" % pid)
            if pid:
                return pid
            else:
                if i > 20:
                    verbose(sys._getframe().f_code.co_name, "Could not get pid for %s" % bin)
                    return None
                time.sleep(i * DELAY_PRECISION)
                i += 1
        except Pyro4.errors.ConnectionClosedError as e:
            if i > 20:
                print(e)
                return None
            time.sleep(i * DELAY_PRECISION)
            i += 1


def check_killed(server, bin):
    i = 1
    while True:
        try:
            server.check_killed(bin)
            verbose(sys._getframe().f_code.co_name, "%s is killed" % bin)
            break
        except Pyro4.errors.ConnectionClosedError as e:
            if i > 20:
                raise Exception("Process was not killed")
            time.sleep(i * DELAY_PRECISION)
            i += 1


def run(server, command, cwd):
    server.run(command, cwd)


def run_and_infect(server, addr, bin, cwd):
    server.run_and_infect(addr, bin, cwd)
    pid = check_pid(server, bin)
    verbose(sys._getframe().f_code.co_name, "%s is now halted" % bin)
    verbose(sys._getframe().f_code.co_name, "Addr is %s" % addr)
    verbose(sys._getframe().f_code.co_name, "PID is %s" % pid)
    return pid


def dump(server, bin, pid, cwd):
    server.dump(pid, cwd)
    # check_killed(server, bin)
    verbose(sys._getframe().f_code.co_name, "%s is dumped" % bin)


def transform(server, bin, tgt, dir, debug = 'n'):
    server.transform(bin, tgt, dir, debug)


def restore(server, bin, cwd):
    try:
        server.restore(bin, cwd)
    except Pyro4.errors.ConnectionClosedError as e:
        print(e) #log it and move forward
    check_pid(server, bin)
    verbose(sys._getframe().f_code.co_name, "%s is restored" % bin)


def restore_and_infect(server, bin, cwd, pid, addr):
    try:
        server.restore_and_infect(bin, cwd, pid, addr)
    except Pyro4.errors.ConnectionClosedError as e:
        print(e) #log it and move forward
    check_pid(server, bin)
    verbose(sys._getframe().f_code.co_name, "%s is restored and infected" % pid)
    verbose(sys._getframe().f_code.co_name, "Addr is %s" % addr)
    verbose(sys._getframe().f_code.co_name, "PID is %s" % pid)


def parse_instruction(instr_id, data, x86_64_server, aarch64_server, cwd, bin, pid):
    if instr_id not in data:
        raise Exception("Instruction id provided not defined")
    instr = data[instr_id]
    if instr["host"] == X86_64:
        server = x86_64_server
    elif instr["host"] == AARCH64:
        server = aarch64_server
    else:
        raise Exception("Host mentioned in config file not supported!")
    if instr["type"] == RUN:
        run(server, instr["command"], cwd)
        return (False, None)
    elif instr["type"] == RUN_AND_INFECT:
        pid = run_and_infect(server, instr["addr"], bin, cwd)
        return (True, pid)
    elif instr["type"] == DUMP:
        if not pid:
            raise Exception("Need a PID with DUMP")
        dump(server, bin, pid, cwd)
        return (False, None)
    elif instr["type"] == TRANSFORM:
        transform(server, bin, instr["target"], cwd)
        return (False, None)
    elif instr["type"] == RESTORE:
        restore(server, bin, cwd)
        return (False, None)
    elif instr["type"] == RESTORE_AND_INFECT:
        if not pid:
            raise Exception("Need a PID with RESTORE_AND_INFECT")
        restore_and_infect(server, bin, cwd, pid, instr["addr"])
        return (False, None)
    else:
        raise Exception("Instruction type not defined")


def main(argv):
    cwd = None
    global VERBOSE
    VERBOSE = False
    try:
        opts, args = getopt.getopt(argv, "hd:v")
    except getopt.GetoptError:
        print("Incorrect usage. Usage: python3 controller_client.py -d <path_to_working_dir>")
        sys.exit(2)
    for opt, arg in opts:
        if opt == "-h":
            print("Usage: python3 controller_client.py -d <path_to_working_dir>")
            sys.exit()
        elif opt == "-d":
            cwd = arg
        elif opt == '-v':
            VERBOSE = True
        else:
            print("Incorrect usage. Usage: python3 controller_client.py -d <path_to_working_dir>")
            sys.exit(2)
    if not cwd:
        print("Incorrect usage. Usage: python3 controller_client.py -d <path_to_working_dir>")
        sys.exit(2)
    assert os.path.exists(cwd), "Working directory does not exist"
    assert os.path.exists(os.path.join(cwd, CONFIG_FILE_NAME)), "Need a config file in working dir"

    f = open(os.path.join(cwd, CONFIG_FILE_NAME))
    data = json.load(f)
    
    bin = data["bin"]

    x86_64_server = Pyro4.Proxy("PYRONAME:%s" % X86_64_SERVER_NAME)
    aarch64_server = Pyro4.Proxy("PYRONAME:%s" % AARCH64_SERVER_NAME)

    pid = None

    for ex in data["execution"]:
        freq = ex["freq"]
        i = 0
        if freq < 0:
            def f(i):
                return True
        else:
            def f(i):
                ret = i < freq
                return ret
        while f(i):
            i += 1
            for seq in ex["sequence"]:
                (ret, val) = parse_instruction(seq, data["instructions"], x86_64_server, aarch64_server, cwd, bin, pid)
                if ret:
                    pid = val


if __name__ == "__main__":
    main(sys.argv[1:])