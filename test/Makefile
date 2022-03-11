
#FIXME Path to TranProc
TRANPROC := /root/TranProc

CRIU := $(TRANPROC)/criu-3.15/criu/criu
CRIT := $(TRANPROC)/criu-3.15/crit/crit
PYTHON := $(shell which python3)
CURR := $(shell pwd)

BINDIR := $(CURR)/bin

CP := cp

PID := 1234
TGT := aarch64
BIN := test
DEBUG := y

dump:
	$(CRIU) dump -vvv --shell-job -o dump.log -t $(PID)

transform:
	$(PYTHON) $(CRIT) recode $(CURR) $(CURR)/$(TGT) $(TGT) $(BIN) $(BINDIR) $(DEBUG) 

shuffle:
	$(PYTHON) $(CRIT) examine $(CURR) $(BIN) code > code.beforeshuffle
	$(PYTHON) $(CRIT) examine $(CURR) $(BIN) stack > stack.beforeshuffle
	$(PYTHON) $(CRIT) elf $(CURR) dump_sm $(BIN) > stackmap.beforeshuffle

	$(PYTHON) $(CRIT) ss $(CURR) $(BIN)

	$(PYTHON) $(CRIT) examine $(CURR) $(BIN) code > code.aftershuffle
	$(PYTHON) $(CRIT) examine $(CURR) $(BIN) stack > stack.aftershuffle
	$(PYTHON) $(CRIT) elf $(CURR) dump_sm $(BIN) > stackmap.aftershuffle	

restore:
	chmod +x $(BIN)
	$(CRIU) restore -vvv --shell-job -o restore.log
