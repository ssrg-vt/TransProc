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
❯ make -C tools/ local-build
```
After this step, you should have CRIU/CRIT binaries generated:
```
❯ find . -type f \( -name criu -o -name crit \)
./criu-3.15/crit/crit
./criu-3.15/criu/criu
❯ ls tools
attach_pid  debugger  ...
```

## How to run a provided test
The TranProc util is tested for a SNU-NPB serial benchmarks  migrated from x86-64 to aarch64.
The test binary is placed inside the test/SNU_NPB_SER_C directory. These tests are 
compiled for x86-64 and aarch64 with the popcorn compiler.
Before recreating the test, please make sure the following things are in place:
- Both source and destination hosts should have the same cgroups.
- ASLR should be disabled on both the hosts. To disable ASLR run `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`.
- The restore location `pwd` command should yield the same output for both source and destination hosts
where you will be checkpointing and restoring the binaries. 
- Place the x86-64 version of the file and the aarch64 version of the file in the bin directory within the directory where you
will be checkpointing. For x86-64 host copy the bt_x86-64 file in the same location and remove the \_x86-64 suffix.
The tree command should yield the following output.
```
.
├── bin
│   ├── bt_aarch64
│   └── bt_x86-64
└── bt
```
Both bt and bt_x86-64 are the exact same files just with different names. 
(bt is used as an example for SNU_NPB benchmarks, can be replaced by others like cg, ep, etc.)
- Build debugger.c placed inside the tools directory with gcc for the source host.
- Stay in the directory containing the test binaries and run the following command:
` $dir_containing_debugger/debugger bt 0x50146f` (For every benchmark, the address after migrate function call should be the used).
- After this is done place the Makefile from $TranProc/test/ directory to the directory containing the test binaries and edit
the variables with approproate values.
- Run `make dump` to dump the running application.
- Run `make transform` to create the transformed image files. The transformed files will be inside aarch64 directory.
- Copy all of these files on the destination host. Please make sure that `pwd` command yields the same output on source
and destination hosts where the files are placed. 
- Also copy the Makefile on the destination directory and edit all appropriate variables.
- Run `make restore` to restore the application on destination.
- From a seperate shell terminal on the destination, run `kill -SIGCONT $PID` where $PID is the pid of the restored binary. 
