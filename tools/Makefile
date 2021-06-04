CC		:= gcc

all: debugger attach_pid

debugger: debugger.c
	$(CC) -o $@ $<

attach_pid: attach_pid.c
	$(CC) -o $@ $<

clean:
	rm -rf debugger attach_pid
