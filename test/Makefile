
#FIXME Path to TranProc
TRANPROC := /root/TranProc

CRIU := $(TRANPROC)/criu-3.15/criu/criu
CRIT := $(TRANPROC)/criu-3.15/crit/crit

CURR := $(shell pwd)

BINDIR := $(CURR)/bin

CP := cp

PID := 1234
TGT := aarch64
BIN := test
DEBUG := y

dump:
	$(CRIU) dump -vvv -o dump.log -t $(PID) --shell-job && echo OK

transform:
	$(CRIT) recode $(CURR) $(CURR)/$(TGT) $(TGT) $(BIN) $(BINDIR) $(DEBUG) 

restore:
	$(CRIU) restore -vvv -o restore.log --shell-job
