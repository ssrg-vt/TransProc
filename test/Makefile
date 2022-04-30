
#FIXME Path to TranProc
TRANPROC := /root/TranProc

CRIU := $(TRANPROC)/criu-3.15/criu/criu
CRIT := $(TRANPROC)/criu-3.15/crit/crit

DEBUGGER := $(TRANPROC)/tools/debugger

TRACER := $(TRANPROC)/tools/tracer

CURR := $(shell pwd)

BINDIR := $(CURR)/bin

CP := cp

ADDR := 0x501242
PID := 1234
TGT := aarch64
BIN := test
DEBUG := y

spawn:
	$(DEBUGGER) $(BIN) $(ADDR)

trace:
	$(TRACER) $(PID)

dump:
	$(CRIU) dump -vvv --shell-job -o dump.log -t $(PID)

transform:
	$(CRIT) recode $(CURR) $(CURR)/$(TGT) $(TGT) $(BIN) $(BINDIR) $(DEBUG) 

restore:
	chmod +x $(BIN)
	$(CRIU) restore -vvv --shell-job -o restore.log
