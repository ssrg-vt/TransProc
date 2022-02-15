import json
import sys
import getopt
import os
import Pyro4
import Pyro4.util

X86_64 = "x86-64"
AARCH64 = "aarch64"

CONFIG_FILE_NAME = "config.json"

X86_64_SERVER_NAME = "stack_pop.controller_daemon.x86_64"
AARCH64_SERVER_NAME = "stack_pop.controller_daemon.aarch64"

"""
Instruct Modes:
"""
RUN = "run"
RUN_AND_INFECT = "run_and_infect"
DUMP = "dump"
TRANSFORM = "transform"
RESTORE = "restore"
RESTORE_AND_INFECT = "restore_and_infect"


def run(server, command, cwd):
    server.run(command, cwd)


def run_and_infect(server, addr, bin, cwd):
    server.run_and_infect(addr, bin, cwd)
    pid = server.check_pid(bin)
    return pid


def dump(server, bin, pid, cwd):
    server.dump(pid, cwd)
    server.check_killed(bin)


def transform(server, bin, tgt, dir, debug = 'n'):
    server.transform(bin, tgt, dir, debug)


def restore(server, bin, cwd):
    server.restore(bin, cwd)
    server.check_pid(bin)


def restore_and_infect(server, bin, cwd, pid, addr):
    server.restore_and_infect(bin, cwd, pid, addr)
    server.check_pid(bin)


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
    elif instr["type"] == RUN_AND_INFECT:
        pid = run_and_infect(server, instr["addr"], bin, cwd)
    elif instr["type"] == DUMP:
        if not pid:
            raise Exception("Need a PID with DUMP")
        dump(server, bin, pid, cwd)
    elif instr["type"] == TRANSFORM:
        transform(server, bin, instr["target"], cwd)
    elif instr["type"] == RESTORE:
        restore(server, bin, cwd)
    elif instr["type"] == RESTORE_AND_INFECT:
        restore_and_infect(server, bin, cwd, pid, instr["addr"])
    else:
        raise Exception("Instruction type not defined")


def main(argv):
    cwd = None
    try:
        opts, args = getopt.getopt(argv, "hd:")
    except getopt.GetoptError:
        print("Incorrect usage. Usage: python3 controller_client.py -d <path_to_working_dir>")
        sys.exit(2)
    for opt, arg in opts:
        if opt == "-h":
            print("Usage: python3 controller_client.py -d <path_to_working_dir>")
            sys.exit()
        elif opt == "-d":
            cwd = arg
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
                parse_instruction(seq, data["instructions"], x86_64_server, aarch64_server, cwd, bin, pid)

if __name__ == "__main__":
    main(sys.argv[1:])