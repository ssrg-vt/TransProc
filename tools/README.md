# Tools

## Debugger
Used to suspend an application at a program point specified by the address. 

### Running the app
./debugger [/path/to/application/binary] [addressOfLineWhereToSuspendInHex]

eg. `./debugger ~/temp/testBin 0x00501031` 
The above command will suspend the testBin app at address `0x00501031`.

## Attach to the target process
Use `./test/loop` as an example. First, obtain the address of `func_path_a` and run it:
```
❯ nm test/loop/loop -ngS | grep "func_path_a"
0000000000401cb5 0000000000000077 T func_path_a
❯ ./test/loop/loop -a
pid: 87282, cnt: 5 
In function func_path_a.
1 
2 
3 
4 
5 
Finish func_path_a.
In function func_path_b.
[1]  + 87282 suspended (signal)  ./test/loop/loop -a
```

Open another terminal, attach the process and wait it to hit the target function (`func_path_a`):
```
❯ sudo ./tools/attach_pid $(pidof loop) 401cb5
INFO  + Target process PID: 87282   at main (attach_pid.c:134) 
INFO  + The injected trap instr @ 0x401cb5   at main (attach_pid.c:135) 
[87285] debugger started
[87285] Child got a signal: Stopped (signal)
[87285] Child started. RIP = 0x004794f4
[87285] Child got a signal: Trace/breakpoint trap
[87285] Child stopped at RIP = 0x00401cb6
```

Use CRIU to dump the suspended process, and check the dumped stack:
```
❯ ./dump.sh loop
❯ ./criu-3.15/crit/crit x ./vanilla-dump sunw nm ../test/loop/loop
87282
sp: 0x7fffffffddb8

bp: 0x7fffffffddd0
ip: 0x401cb5 (func_path_a + 0)
Stack Contents:
(RBP - 0x18) 0x401d5d (4201821)
(RBP - 0x10) 0x0 (0)
(RBP - 0x8) 0x5004c2018 (21479825432)

bp: 0x7fffffffde00
ip: 0x401e6d (main + 245)
Stack Contents:
(RBP - 0x30) 0x7fffffffde00 (140737488346624)
(RBP - 0x28) 0x401e6d (4202093)
(RBP - 0x20) 0x7fffffffdf38 (140737488346936)
(RBP - 0x18) 0x200402f10 (8594140944)
(RBP - 0x10) 0x100000005 (4294967301)
(RBP - 0x8) 0xffffffff00000000 (18446744069414584320)
```

If we want to **restore** the process from the CRIU image, we can use `sudo ./criu-3.15/criu/criu restore -j -D vanilla-dump`. However, if we use `ps` to find `loop`, it shows the process state is **T** (T    stopped by job control signal). This is cause by the SIGSTOP signal. To continu, we can send a SIGCONT signal to the target process:
```
❯ ps aux | grep loop/loop
xiaogua+   87282  0.0  0.0   1084    44 pts/6    T+   12:04   0:00 ./test/loop/loop -a
❯ kill -18 $(pidof loop)
# loop continue executing when received SIGCONT (#18)
❯ ps aux | grep loop/loop
xiaogua+   87282  0.0  0.0   1084    44 pts/6    S+   12:10   0:00 ./test/loop/loop -a

```