.PHONY: all vdso clean

all:
	make -C criu-3.15 -j$(shell nproc)
	make -C tools

vdso:
	$(shell ./vdso/vdso.sh)

clean:
	make -C criu-3.15 clean
	make -C tools clean
