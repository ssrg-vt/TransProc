# Toolchain
POP		:= /usr/local/popcorn

# Compiler
CC_X86	:= $(POP)/x86_64/bin/musl-clang
CC_ARM	:= $(POP)/aarch64/bin/musl-clang
GCC		:= gcc

# Linker
LD_X86 	:= $(POP)/bin/x86_64-popcorn-linux-gnu-ld
LD_ARM	:= $(POP)/bin/aarch64-popcorn-linux-gnu-ld

# Compiler Flags
CFLAGS	:= -c

# Linker Flags
LDFLAGS_X86	:= $(POP)/x86_64/lib/crt1.o -L$(POP)/x86_64/lib/ -lc
LDFLAGS_ARM	:= $(POP)/aarch64/lib/crt1.o -L$(POP)/aarch64/lib/ -lc -L$(POP)/lib/gcc/aarch64-popcorn-linux-gnu/9.3.0/ -lgcc

all: debugger-x86_64 debugger-aarch64 attach_pid

debugger-x86_64.o: debugger.c
	$(CC_X86) -o $@ $< $(CFLAGS)

debugger-aarch64.o: debugger.c
	$(CC_ARM) -o $@ $< $(CFLAGS)

debugger-x86_64: debugger-x86_64.o
	$(LD_X86) -o $@ $< $(LDFLAGS_X86)

debugger-aarch64: debugger-aarch64.o
	$(LD_ARM) -o $@ $< $(LDFLAGS_ARM)

attach_pid: attach_pid.c
	$(GCC) -o $@ $<

clean:
	rm -rf debugger-x86_64 debugger-aarch64 debugger-x86_64.o debugger-aarch64.o attach_pid