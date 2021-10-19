
#FIXME Path to TranProc
TRANPROC := /home/abhishek/projects/TranProc

CRIU := $(TRANPROC)/criu-3.15/criu/criu
CRIT := $(TRANPROC)/criu-3.15/crit/crit

CURR := $(shell pwd)

CP := cp

PID := 1234

transform:
	$(CRIU) dump -vvv -o dump.log -t $(PID) --shell-job && echo OK
	$(CRIT) recode -d $(CURR) 
	$(CP) test_x86-64 $(CURR)/new_image.aarch64/.
	$(CP) test_aarch64 $(CURR)/new_image.aarch64/.
	$(CP) test_aarch64 $(CURR)/new_image.aarch64/test
	$(CRIT) trans $(CURR) $(CURR)/new_image.aarch64/ all test test_aarch64
	$(CRIT) copy $(CURR)/new_image.aarch64/ stack $(CURR)/dest_stack test_aarch64
	$(CRIT) copy $(CURR)/new_image.aarch64/ code_pages $(CURR)/dest_stack test_aarch64

restore:
	$(CRIU) restore -vvv -o restore.log --shell-job
