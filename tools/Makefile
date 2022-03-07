GCC := gcc

all: debugger attach_pid

attach_pid: attach_pid.c
	$(GCC) -o $@ $<

debugger: debugger.c
	$(GCC) -o $@ $<

clean:
	rm -rf debugger attach_pid
