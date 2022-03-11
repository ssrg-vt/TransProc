# TranProc
Transform the CRIU image between different architectures for vanilla code.

## Build TransProc from source
### Prepare the build environment
You need to have an `x86_64` machine and an `arm64` machine. It's highly recommended that the two machines have the same OS distribution (e.g., Ubuntu 20.04). You can use either [QEMU](https://www.qemu.org/) VMs with [Ubuntu cloud images](https://cloud-images.ubuntu.com/releases/focal/release/), or your laptop with a [Raspberry Pi](https://www.raspberrypi.com/products/raspberry-pi-4-model-b/).

Download the TransProc source code and ensure the source code is in the **same location** on each machine node.
For example, on the Raspberry Pi 4:
```
❯ uname -a
Linux ubuntu 5.4.0-1052-raspi #58-Ubuntu SMP PREEMPT Mon Feb 7 16:52:35 UTC 2022 aarch64 aarch64 aarch64 GNU/Linux
❯ pwd
/home/ubuntu
❯ git clone https://github.com/ssrg-vt/TranProc.git
```

On the x86 laptop or VM:
```
❯ uname -a
Linux x86 5.2.21+ #1 SMP Tue Sep 14 03:36:42 EDT 2021 x86_64 x86_64 x86_64 GNU/Linux
❯ pwd
/home/ubuntu
❯ git clone https://github.com/ssrg-vt/TranProc.git
```

### Install the prerequisites and build CRIU/CRIT binaries
On each node, you need to install the required package first. You can refer to the [criu project page](https://criu.org/Installation) for detail information. Here is an example of the packages needed for Ubuntu 20.04:
```
sudo apt install -y libprotobuf-dev libprotobuf-c-dev protobuf-c-compiler protobuf-compiler python-protobuf pkg-config libnl-3-dev libnet-dev libcap-dev libbsd-dev
```
Build `criu-3.15` and tools for inserting a breakpoint (code migration point):
```
❯ pwd
/home/ubuntu/TranProc
❯ make -C criu-3.15/
❯ make -C tools/
```
After this step, you should have CRIU/CRIT binaries generated:
```
❯ find . -type f \( -name criu -o -name crit \)
./criu-3.15/crit/crit
./criu-3.15/criu/criu
❯ ls tools
attach_pid  debugger  ...
```
The python code provided in this repository has the following dependencies:
`pyelftools, jsonpath-ng, pyro4, psutil and scp`.
Install them as follows:
```
pip install pyelftools
pip install jsonpath-ng
pip install pyro4
pip install psutil
pip install scp
```
Although this code is tested for both python2 and python3, it is strongly recommended to use python3 and pip3. 

## How to run a provided test
### Preparation:
The TranProc util is tested for a SNU-NPB serial benchmarks  migrated from x86-64 to aarch64.
The test binary is placed inside the test/SNU_NPB_SER_C directory. These tests are 
compiled for x86-64 and aarch64 with the popcorn compiler.
Before recreating the test, please make sure the following things are in place:
- Both source and destination hosts should have the same cgroups. Do so by running the following command and matching the output for both the hosts:
`cat /boot/config-$(uname -r) | grep CGROUP`.
- ASLR should be disabled on both the hosts. To disable ASLR run `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`.
- The restore location `pwd` command should yield the same output for both source and destination hosts
where you will be checkpointing and restoring the binaries. 
- Place the x86-64 version of the file and the aarch64 version of the file in the bin directory within the directory where you
will be checkpointing. For x86-64 host copy the bt_x86-64 file in the same location and remove the \_x86-64 suffix.
Also copy the Makefile and config.json file from the test directory inside TranProc to this directory. Update the TranProc location in the Makefile. The tree command should yield the following output.
```
.
├── Makefile
├── bin
│   ├── bt_aarch64
│   └── bt_x86-64
├── bt
└── config.json
```
Both bt and bt_x86-64 are the exact same files just with different names. 
(bt is used as an example for SNU_NPB benchmarks, can be replaced by others like cg, ep, etc.)
- Also make sure that the TranProc repository is copied to the same locations on both source and destination hosts.

### Manual Migration:
- Stay in the directory containing the test binaries and run the following command:
` $TranProc/tools/debugger bt 0x50146f` (For every benchmark, the address after migrate function call should be the used).
- Make a not of the PID of the spawned bt binary.
- Run `make PID=$pid dump` to dump the running application. `$pid` is the actual numeric PID value of bt.
- Run `make BIN=bt TGT=aarch64 transform` to create the transformed image files. The transformed files will be inside aarch64 directory. TGT can be either `aarch64` or `x86-64` depending on the source and destination architectures. (Currently tested for x86-64 as host and aarch64 as destination).
- Copy all of these files on the destination host. Please make sure that `pwd` command yields the same output on source
and destination hosts where the files are placed. 
- Also copy the Makefile on the destination directory and edit all appropriate variables.
- Run `make BIN=bt TGT=aarch64 shuffle` to shuffle the stack frames and update the code pages accordingly. 
- Run `make BIN=bt restore` to restore the application on destination.
- From a seperate shell terminal on the destination, run `kill -SIGCONT $PID` where $PID is the pid of the restored binary. 

### Automated Migration on VMs:
- You can use [QEMU](https://www.qemu.org/) VMs with [Ubuntu cloud images prapared by us](https://drive.google.com/drive/folders/1KPPo4zHts8KLdB_CY1YqfRWuUXfu7Ayx?usp=sharing) to run this test.
- To host these VMs, run the script `init_bridge.sh <NIC Interface>` from the tools directory in TranProc with your network interface.
- Run the `run_x86.sh` script to start the x86-64 host and `run_arm.sh` script to start the aarch64 host.
- Make a note of the local IP addresses of both the VMs.
- On the x86-64 VM, run the following command in a terminal to start pyro4 naming server: 
```
 python -m Pyro4.naming -n your_hostname  # i.e. your_hostname = “192.168.1.99” 
 ```
 - In a separate terminal, navigate to the `$TranProc/tools/` directory and run the following commands on both the x86-64 and aarch64 VMs.
 ```
 export PYRO_HOST=<IP Address> #IP Address = IP of the VM
 python3 controller_daemon.py
 ```
- controller_client.py is the code that parses the config.json file placed in the directory of the benchmark and does automated migration by giving commands to the controller_daemon.
- In a separate terminal on the x86-64 VM, navigate to `$TranProc/tools/` and run the following command:
```
python3 controller_client.py -v -d <path to the benchmark dir>

# If running on our provided VMs
# python3 controller_client.py -v -d /root/bt/
```

