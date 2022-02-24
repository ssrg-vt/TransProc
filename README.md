# TranProc
Transform the CRIU image between different architectures for vanilla code.

## Dependencies
- all criu dependencies listed here: https://criu.org/Installation
- python: pyelftools, jsonpath-ng, pyro4, psutil, scp

## How to run a provided test
The TranProc util is tested for a SNU-NPB serial benchmarks  migrated from x86-64 to aarch64.
The test binary is placed inside the test/SNU_NPB_SER_C directory. These tests are 
compiled for x86-64 and aarch64 with the popcorn compiler.
Before recreating the test, please make sure the following things are in place:
- Both source and destination hosts should have the same cgroups.
- ASLR should be disabled on both the hosts. To disable ASLR run `echo 0 | sudo tee /proc/sys/kernel/randomiza_va_space`.
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
