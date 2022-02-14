import json
import sys
import getopt
import os
import Pyro4
import Pyro4.util

CONFIG_FILE_NAME = "config.json"

X86_64_SERVER_NAME = "stack_pop.controller_daemon.x86-64"
AARCH64_SERVER_NAME = "stack_pop.controller_daemon.aarch64"


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


if __name__ == "__main__":
    main(sys.argv[1:])