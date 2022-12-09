GCC := gcc

all: debugger attach_pid tracer tracer2

attach_pid: attach_pid.c
	$(GCC) -o $@ $<

debugger: debugger.c
	$(GCC) -o $@ $<

tracer: tracer.c
	$(GCC) -pthread -o $@ $<

tracer2: tracer2.c
	$(GCC) -pthread -o $@ $<

clean:
	rm -rf debugger attach_pid tracer tracer2
